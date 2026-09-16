rule TTP_XOR_WriteProcessMemory_1f8d {
  strings:
    $key_1f8d = { 48 ff [2] 7a dd [2] 7c e8 [2] 52 e8 [2] 6d f4 }

  condition:
    any of them
}