rule TTP_XOR_WriteProcessMemory_5a3d {
  strings:
    $key_5a3d = { 0d 4f [2] 3f 6d [2] 39 58 [2] 17 58 [2] 28 44 }

  condition:
    any of them
}