rule TTP_XOR_WriteProcessMemory_6a3d {
  strings:
    $key_6a3d = { 3d 4f [2] 0f 6d [2] 09 58 [2] 27 58 [2] 18 44 }

  condition:
    any of them
}