rule TTP_XOR_WriteProcessMemory_5c34 {
  strings:
    $key_5c34 = { 0b 46 [2] 39 64 [2] 3f 51 [2] 11 51 [2] 2e 4d }

  condition:
    any of them
}