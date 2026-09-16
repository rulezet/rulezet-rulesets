rule TTP_XOR_WriteProcessMemory_4f7d {
  strings:
    $key_4f7d = { 18 0f [2] 2a 2d [2] 2c 18 [2] 02 18 [2] 3d 04 }

  condition:
    any of them
}