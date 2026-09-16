rule TTP_XOR_WriteProcessMemory_cd15 {
  strings:
    $key_cd15 = { 9a 67 [2] a8 45 [2] ae 70 [2] 80 70 [2] bf 6c }

  condition:
    any of them
}