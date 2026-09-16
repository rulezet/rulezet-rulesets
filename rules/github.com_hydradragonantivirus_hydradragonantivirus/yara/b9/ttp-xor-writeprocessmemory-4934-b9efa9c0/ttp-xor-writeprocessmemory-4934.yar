rule TTP_XOR_WriteProcessMemory_4934 {
  strings:
    $key_4934 = { 1e 46 [2] 2c 64 [2] 2a 51 [2] 04 51 [2] 3b 4d }

  condition:
    any of them
}