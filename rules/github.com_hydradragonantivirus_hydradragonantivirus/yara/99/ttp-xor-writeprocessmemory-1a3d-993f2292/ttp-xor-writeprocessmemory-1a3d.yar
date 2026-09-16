rule TTP_XOR_WriteProcessMemory_1a3d {
  strings:
    $key_1a3d = { 4d 4f [2] 7f 6d [2] 79 58 [2] 57 58 [2] 68 44 }

  condition:
    any of them
}