rule TTP_XOR_WriteProcessMemory_cd25 {
  strings:
    $key_cd25 = { 9a 57 [2] a8 75 [2] ae 40 [2] 80 40 [2] bf 5c }

  condition:
    any of them
}