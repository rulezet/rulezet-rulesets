rule TTP_XOR_WriteProcessMemory_cde6 {
  strings:
    $key_cde6 = { 9a 94 [2] a8 b6 [2] ae 83 [2] 80 83 [2] bf 9f }

  condition:
    any of them
}