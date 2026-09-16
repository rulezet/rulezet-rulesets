rule TTP_XOR_WriteProcessMemory_7934 {
  strings:
    $key_7934 = { 2e 46 [2] 1c 64 [2] 1a 51 [2] 34 51 [2] 0b 4d }

  condition:
    any of them
}