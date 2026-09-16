rule TTP_XOR_WriteProcessMemory_cc84 {
  strings:
    $key_cc84 = { 9b f6 [2] a9 d4 [2] af e1 [2] 81 e1 [2] be fd }

  condition:
    any of them
}