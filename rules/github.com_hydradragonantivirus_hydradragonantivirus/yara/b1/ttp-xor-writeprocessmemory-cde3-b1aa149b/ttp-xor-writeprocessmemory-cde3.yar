rule TTP_XOR_WriteProcessMemory_cde3 {
  strings:
    $key_cde3 = { 9a 91 [2] a8 b3 [2] ae 86 [2] 80 86 [2] bf 9a }

  condition:
    any of them
}