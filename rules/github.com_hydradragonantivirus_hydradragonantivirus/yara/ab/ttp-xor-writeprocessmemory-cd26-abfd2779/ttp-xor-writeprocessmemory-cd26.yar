rule TTP_XOR_WriteProcessMemory_cd26 {
  strings:
    $key_cd26 = { 9a 54 [2] a8 76 [2] ae 43 [2] 80 43 [2] bf 5f }

  condition:
    any of them
}