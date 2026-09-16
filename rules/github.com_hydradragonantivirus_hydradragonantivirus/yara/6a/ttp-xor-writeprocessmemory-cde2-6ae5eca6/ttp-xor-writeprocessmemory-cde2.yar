rule TTP_XOR_WriteProcessMemory_cde2 {
  strings:
    $key_cde2 = { 9a 90 [2] a8 b2 [2] ae 87 [2] 80 87 [2] bf 9b }

  condition:
    any of them
}