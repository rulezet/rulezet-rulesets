rule TTP_XOR_WriteProcessMemory_cd35 {
  strings:
    $key_cd35 = { 9a 47 [2] a8 65 [2] ae 50 [2] 80 50 [2] bf 4c }

  condition:
    any of them
}