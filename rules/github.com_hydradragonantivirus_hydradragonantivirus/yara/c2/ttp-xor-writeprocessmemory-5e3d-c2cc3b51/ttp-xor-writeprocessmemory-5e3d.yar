rule TTP_XOR_WriteProcessMemory_5e3d {
  strings:
    $key_5e3d = { 09 4f [2] 3b 6d [2] 3d 58 [2] 13 58 [2] 2c 44 }

  condition:
    any of them
}