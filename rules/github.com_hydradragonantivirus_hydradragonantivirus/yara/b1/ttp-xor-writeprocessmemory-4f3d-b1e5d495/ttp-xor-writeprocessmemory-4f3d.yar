rule TTP_XOR_WriteProcessMemory_4f3d {
  strings:
    $key_4f3d = { 18 4f [2] 2a 6d [2] 2c 58 [2] 02 58 [2] 3d 44 }

  condition:
    any of them
}