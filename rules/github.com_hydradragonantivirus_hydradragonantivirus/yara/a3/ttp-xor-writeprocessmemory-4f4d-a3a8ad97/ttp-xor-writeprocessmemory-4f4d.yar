rule TTP_XOR_WriteProcessMemory_4f4d {
  strings:
    $key_4f4d = { 18 3f [2] 2a 1d [2] 2c 28 [2] 02 28 [2] 3d 34 }

  condition:
    any of them
}