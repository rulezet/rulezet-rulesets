rule TTP_XOR_WriteProcessMemory_5ff0 {
  strings:
    $key_5ff0 = { 08 82 [2] 3a a0 [2] 3c 95 [2] 12 95 [2] 2d 89 }

  condition:
    any of them
}