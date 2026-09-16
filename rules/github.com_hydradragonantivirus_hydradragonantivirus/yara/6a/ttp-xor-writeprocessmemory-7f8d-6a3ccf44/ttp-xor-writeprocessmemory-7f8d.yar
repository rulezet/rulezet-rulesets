rule TTP_XOR_WriteProcessMemory_7f8d {
  strings:
    $key_7f8d = { 28 ff [2] 1a dd [2] 1c e8 [2] 32 e8 [2] 0d f4 }

  condition:
    any of them
}