rule TTP_XOR_WriteProcessMemory_cd72 {
  strings:
    $key_cd72 = { 9a 00 [2] a8 22 [2] ae 17 [2] 80 17 [2] bf 0b }

  condition:
    any of them
}