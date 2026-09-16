rule TTP_XOR_WriteProcessMemory_cd56 {
  strings:
    $key_cd56 = { 9a 24 [2] a8 06 [2] ae 33 [2] 80 33 [2] bf 2f }

  condition:
    any of them
}