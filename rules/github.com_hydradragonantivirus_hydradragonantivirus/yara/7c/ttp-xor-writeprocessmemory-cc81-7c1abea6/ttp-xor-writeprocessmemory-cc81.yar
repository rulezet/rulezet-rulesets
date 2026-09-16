rule TTP_XOR_WriteProcessMemory_cc81 {
  strings:
    $key_cc81 = { 9b f3 [2] a9 d1 [2] af e4 [2] 81 e4 [2] be f8 }

  condition:
    any of them
}