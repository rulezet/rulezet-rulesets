rule TTP_XOR_WriteProcessMemory_5ff5 {
  strings:
    $key_5ff5 = { 08 87 [2] 3a a5 [2] 3c 90 [2] 12 90 [2] 2d 8c }

  condition:
    any of them
}