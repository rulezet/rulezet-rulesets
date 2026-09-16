rule TTP_XOR_WriteProcessMemory_0384 {
  strings:
    $key_0384 = { 54 f6 [2] 66 d4 [2] 60 e1 [2] 4e e1 [2] 71 fd }

  condition:
    any of them
}