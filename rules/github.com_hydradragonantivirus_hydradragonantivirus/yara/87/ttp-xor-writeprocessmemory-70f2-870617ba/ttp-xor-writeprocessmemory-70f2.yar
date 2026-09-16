rule TTP_XOR_WriteProcessMemory_70f2 {
  strings:
    $key_70f2 = { 27 80 [2] 15 a2 [2] 13 97 [2] 3d 97 [2] 02 8b }

  condition:
    any of them
}