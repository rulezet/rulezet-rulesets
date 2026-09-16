rule TTP_XOR_WriteProcessMemory_1b8d {
  strings:
    $key_1b8d = { 4c ff [2] 7e dd [2] 78 e8 [2] 56 e8 [2] 69 f4 }

  condition:
    any of them
}