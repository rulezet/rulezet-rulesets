rule TTP_XOR_WriteProcessMemory_4f8c {
  strings:
    $key_4f8c = { 18 fe [2] 2a dc [2] 2c e9 [2] 02 e9 [2] 3d f5 }

  condition:
    any of them
}