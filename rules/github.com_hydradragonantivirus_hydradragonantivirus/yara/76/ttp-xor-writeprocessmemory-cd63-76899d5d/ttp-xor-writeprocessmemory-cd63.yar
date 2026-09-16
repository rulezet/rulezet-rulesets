rule TTP_XOR_WriteProcessMemory_cd63 {
  strings:
    $key_cd63 = { 9a 11 [2] a8 33 [2] ae 06 [2] 80 06 [2] bf 1a }

  condition:
    any of them
}