rule TTP_XOR_WriteProcessMemory_2c3d {
  strings:
    $key_2c3d = { 7b 4f [2] 49 6d [2] 4f 58 [2] 61 58 [2] 5e 44 }

  condition:
    any of them
}