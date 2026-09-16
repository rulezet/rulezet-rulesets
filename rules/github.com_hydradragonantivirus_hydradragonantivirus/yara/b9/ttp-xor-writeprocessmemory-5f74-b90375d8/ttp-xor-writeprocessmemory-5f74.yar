rule TTP_XOR_WriteProcessMemory_5f74 {
  strings:
    $key_5f74 = { 08 06 [2] 3a 24 [2] 3c 11 [2] 12 11 [2] 2d 0d }

  condition:
    any of them
}