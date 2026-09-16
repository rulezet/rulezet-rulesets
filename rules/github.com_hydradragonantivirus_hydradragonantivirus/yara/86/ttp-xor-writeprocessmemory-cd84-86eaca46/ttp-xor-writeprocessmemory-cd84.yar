rule TTP_XOR_WriteProcessMemory_cd84 {
  strings:
    $key_cd84 = { 9a f6 [2] a8 d4 [2] ae e1 [2] 80 e1 [2] bf fd }

  condition:
    any of them
}