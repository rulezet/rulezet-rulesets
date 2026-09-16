rule TTP_XOR_WriteProcessMemory_f3b0 {
  strings:
    $key_f3b0 = { a4 c2 [2] 96 e0 [2] 90 d5 [2] be d5 [2] 81 c9 }

  condition:
    any of them
}