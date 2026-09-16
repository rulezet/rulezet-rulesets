rule TTP_XOR_WriteProcessMemory_c712 {
  strings:
    $key_c712 = { 90 60 [2] a2 42 [2] a4 77 [2] 8a 77 [2] b5 6b }

  condition:
    any of them
}