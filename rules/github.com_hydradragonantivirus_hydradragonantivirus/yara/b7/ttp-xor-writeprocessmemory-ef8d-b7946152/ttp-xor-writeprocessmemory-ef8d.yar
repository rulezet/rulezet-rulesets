rule TTP_XOR_WriteProcessMemory_ef8d {
  strings:
    $key_ef8d = { b8 ff [2] 8a dd [2] 8c e8 [2] a2 e8 [2] 9d f4 }

  condition:
    any of them
}