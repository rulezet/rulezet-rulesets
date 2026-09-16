rule TTP_XOR_WriteProcessMemory_5e9d {
  strings:
    $key_5e9d = { 09 ef [2] 3b cd [2] 3d f8 [2] 13 f8 [2] 2c e4 }

  condition:
    any of them
}