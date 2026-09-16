rule TTP_XOR_WriteProcessMemory_5f73 {
  strings:
    $key_5f73 = { 08 01 [2] 3a 23 [2] 3c 16 [2] 12 16 [2] 2d 0a }

  condition:
    any of them
}