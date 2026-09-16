rule TTP_XOR_WriteProcessMemory_f6b8 {
  strings:
    $key_f6b8 = { a1 ca [2] 93 e8 [2] 95 dd [2] bb dd [2] 84 c1 }

  condition:
    any of them
}