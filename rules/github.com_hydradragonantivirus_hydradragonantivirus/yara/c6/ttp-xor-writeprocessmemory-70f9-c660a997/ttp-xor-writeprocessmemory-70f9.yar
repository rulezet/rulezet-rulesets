rule TTP_XOR_WriteProcessMemory_70f9 {
  strings:
    $key_70f9 = { 27 8b [2] 15 a9 [2] 13 9c [2] 3d 9c [2] 02 80 }

  condition:
    any of them
}