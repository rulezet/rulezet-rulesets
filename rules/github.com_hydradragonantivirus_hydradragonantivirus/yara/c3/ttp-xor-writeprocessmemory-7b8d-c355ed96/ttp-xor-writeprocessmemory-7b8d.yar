rule TTP_XOR_WriteProcessMemory_7b8d {
  strings:
    $key_7b8d = { 2c ff [2] 1e dd [2] 18 e8 [2] 36 e8 [2] 09 f4 }

  condition:
    any of them
}