rule TTP_XOR_WriteProcessMemory_cd46 {
  strings:
    $key_cd46 = { 9a 34 [2] a8 16 [2] ae 23 [2] 80 23 [2] bf 3f }

  condition:
    any of them
}