rule TTP_XOR_WriteProcessMemory_cc61 {
  strings:
    $key_cc61 = { 9b 13 [2] a9 31 [2] af 04 [2] 81 04 [2] be 18 }

  condition:
    any of them
}