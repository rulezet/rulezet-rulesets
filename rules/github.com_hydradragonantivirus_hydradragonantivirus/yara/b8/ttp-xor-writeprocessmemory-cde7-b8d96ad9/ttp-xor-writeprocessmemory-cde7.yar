rule TTP_XOR_WriteProcessMemory_cde7 {
  strings:
    $key_cde7 = { 9a 95 [2] a8 b7 [2] ae 82 [2] 80 82 [2] bf 9e }

  condition:
    any of them
}