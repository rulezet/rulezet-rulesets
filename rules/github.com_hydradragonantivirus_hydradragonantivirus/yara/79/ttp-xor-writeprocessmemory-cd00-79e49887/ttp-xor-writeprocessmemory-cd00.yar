rule TTP_XOR_WriteProcessMemory_cd00 {
  strings:
    $key_cd00 = { 9a 72 [2] a8 50 [2] ae 65 [2] 80 65 [2] bf 79 }

  condition:
    any of them
}