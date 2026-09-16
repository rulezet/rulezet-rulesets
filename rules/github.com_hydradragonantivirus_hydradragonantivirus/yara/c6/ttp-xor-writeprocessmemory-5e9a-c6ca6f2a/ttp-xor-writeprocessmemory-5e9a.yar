rule TTP_XOR_WriteProcessMemory_5e9a {
  strings:
    $key_5e9a = { 09 e8 [2] 3b ca [2] 3d ff [2] 13 ff [2] 2c e3 }

  condition:
    any of them
}