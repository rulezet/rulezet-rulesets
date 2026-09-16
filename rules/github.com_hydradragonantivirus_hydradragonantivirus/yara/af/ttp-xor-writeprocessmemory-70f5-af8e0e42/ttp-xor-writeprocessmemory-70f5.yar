rule TTP_XOR_WriteProcessMemory_70f5 {
  strings:
    $key_70f5 = { 27 87 [2] 15 a5 [2] 13 90 [2] 3d 90 [2] 02 8c }

  condition:
    any of them
}