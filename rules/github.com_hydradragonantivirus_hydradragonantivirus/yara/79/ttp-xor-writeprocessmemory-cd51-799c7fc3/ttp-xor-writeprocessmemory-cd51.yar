rule TTP_XOR_WriteProcessMemory_cd51 {
  strings:
    $key_cd51 = { 9a 23 [2] a8 01 [2] ae 34 [2] 80 34 [2] bf 28 }

  condition:
    any of them
}