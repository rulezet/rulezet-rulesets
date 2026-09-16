rule TTP_XOR_WriteProcessMemory_0b8d {
  strings:
    $key_0b8d = { 5c ff [2] 6e dd [2] 68 e8 [2] 46 e8 [2] 79 f4 }

  condition:
    any of them
}