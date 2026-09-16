rule TTP_XOR_WriteProcessMemory_cc12 {
  strings:
    $key_cc12 = { 9b 60 [2] a9 42 [2] af 77 [2] 81 77 [2] be 6b }

  condition:
    any of them
}