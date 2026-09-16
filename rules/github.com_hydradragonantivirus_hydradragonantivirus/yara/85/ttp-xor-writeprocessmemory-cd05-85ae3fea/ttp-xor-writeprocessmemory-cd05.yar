rule TTP_XOR_WriteProcessMemory_cd05 {
  strings:
    $key_cd05 = { 9a 77 [2] a8 55 [2] ae 60 [2] 80 60 [2] bf 7c }

  condition:
    any of them
}