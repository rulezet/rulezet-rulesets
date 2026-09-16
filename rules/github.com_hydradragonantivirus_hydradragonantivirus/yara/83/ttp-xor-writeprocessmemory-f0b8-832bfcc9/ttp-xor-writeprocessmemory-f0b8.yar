rule TTP_XOR_WriteProcessMemory_f0b8 {
  strings:
    $key_f0b8 = { a7 ca [2] 95 e8 [2] 93 dd [2] bd dd [2] 82 c1 }

  condition:
    any of them
}