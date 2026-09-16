rule TTP_XOR_WriteProcessMemory_cd40 {
  strings:
    $key_cd40 = { 9a 32 [2] a8 10 [2] ae 25 [2] 80 25 [2] bf 39 }

  condition:
    any of them
}