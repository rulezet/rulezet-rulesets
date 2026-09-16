rule TTP_XOR_WriteProcessMemory_6f8d {
  strings:
    $key_6f8d = { 38 ff [2] 0a dd [2] 0c e8 [2] 22 e8 [2] 1d f4 }

  condition:
    any of them
}