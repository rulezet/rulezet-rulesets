rule TTP_XOR_WriteProcessMemory_188d {
  strings:
    $key_188d = { 4f ff [2] 7d dd [2] 7b e8 [2] 55 e8 [2] 6a f4 }

  condition:
    any of them
}