rule TTP_XOR_WriteProcessMemory_418d {
  strings:
    $key_418d = { 16 ff [2] 24 dd [2] 22 e8 [2] 0c e8 [2] 33 f4 }

  condition:
    any of them
}