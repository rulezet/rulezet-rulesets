rule TTP_XOR_WriteProcessMemory_5f42 {
  strings:
    $key_5f42 = { 08 30 [2] 3a 12 [2] 3c 27 [2] 12 27 [2] 2d 3b }

  condition:
    any of them
}