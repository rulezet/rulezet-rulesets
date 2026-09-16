rule TTP_XOR_WriteProcessMemory_cd02 {
  strings:
    $key_cd02 = { 9a 70 [2] a8 52 [2] ae 67 [2] 80 67 [2] bf 7b }

  condition:
    any of them
}