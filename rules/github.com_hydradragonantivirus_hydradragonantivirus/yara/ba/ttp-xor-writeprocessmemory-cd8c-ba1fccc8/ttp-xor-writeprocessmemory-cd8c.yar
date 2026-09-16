rule TTP_XOR_WriteProcessMemory_cd8c {
  strings:
    $key_cd8c = { 9a fe [2] a8 dc [2] ae e9 [2] 80 e9 [2] bf f5 }

  condition:
    any of them
}