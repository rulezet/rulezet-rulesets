rule TTP_XOR_WriteProcessMemory_cc77 {
  strings:
    $key_cc77 = { 9b 05 [2] a9 27 [2] af 12 [2] 81 12 [2] be 0e }

  condition:
    any of them
}