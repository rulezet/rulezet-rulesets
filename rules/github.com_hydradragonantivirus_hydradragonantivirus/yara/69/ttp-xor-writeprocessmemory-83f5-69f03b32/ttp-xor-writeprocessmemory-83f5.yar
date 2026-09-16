rule TTP_XOR_WriteProcessMemory_83f5 {
  strings:
    $key_83f5 = { d4 87 [2] e6 a5 [2] e0 90 [2] ce 90 [2] f1 8c }

  condition:
    any of them
}