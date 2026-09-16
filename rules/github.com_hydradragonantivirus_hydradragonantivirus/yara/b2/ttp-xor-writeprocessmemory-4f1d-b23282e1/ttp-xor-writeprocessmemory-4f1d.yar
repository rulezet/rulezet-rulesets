rule TTP_XOR_WriteProcessMemory_4f1d {
  strings:
    $key_4f1d = { 18 6f [2] 2a 4d [2] 2c 78 [2] 02 78 [2] 3d 64 }

  condition:
    any of them
}