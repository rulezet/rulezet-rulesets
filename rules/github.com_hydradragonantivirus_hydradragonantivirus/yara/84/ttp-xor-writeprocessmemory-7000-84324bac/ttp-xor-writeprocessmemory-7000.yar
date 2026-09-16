rule TTP_XOR_WriteProcessMemory_7000 {
  strings:
    $key_7000 = { 27 72 [2] 15 50 [2] 13 65 [2] 3d 65 [2] 02 79 }

  condition:
    any of them
}