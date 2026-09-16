rule TTP_XOR_WriteProcessMemory_cd81 {
  strings:
    $key_cd81 = { 9a f3 [2] a8 d1 [2] ae e4 [2] 80 e4 [2] bf f8 }

  condition:
    any of them
}