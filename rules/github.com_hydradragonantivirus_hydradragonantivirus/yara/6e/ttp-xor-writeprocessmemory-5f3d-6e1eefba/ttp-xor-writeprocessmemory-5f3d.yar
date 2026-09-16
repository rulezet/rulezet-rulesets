rule TTP_XOR_WriteProcessMemory_5f3d {
  strings:
    $key_5f3d = { 08 4f [2] 3a 6d [2] 3c 58 [2] 12 58 [2] 2d 44 }

  condition:
    any of them
}