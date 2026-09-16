rule TTP_XOR_WriteProcessMemory_3d4d {
  strings:
    $key_3d4d = { 6a 3f [2] 58 1d [2] 5e 28 [2] 70 28 [2] 4f 34 }

  condition:
    any of them
}