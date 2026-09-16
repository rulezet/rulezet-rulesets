rule TTP_XOR_WriteProcessMemory_cd66 {
  strings:
    $key_cd66 = { 9a 14 [2] a8 36 [2] ae 03 [2] 80 03 [2] bf 1f }

  condition:
    any of them
}