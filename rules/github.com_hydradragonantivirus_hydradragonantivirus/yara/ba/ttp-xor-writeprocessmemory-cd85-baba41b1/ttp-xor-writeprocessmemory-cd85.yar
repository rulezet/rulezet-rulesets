rule TTP_XOR_WriteProcessMemory_cd85 {
  strings:
    $key_cd85 = { 9a f7 [2] a8 d5 [2] ae e0 [2] 80 e0 [2] bf fc }

  condition:
    any of them
}