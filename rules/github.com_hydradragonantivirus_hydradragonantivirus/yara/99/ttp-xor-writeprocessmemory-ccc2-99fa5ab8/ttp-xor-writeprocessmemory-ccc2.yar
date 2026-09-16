rule TTP_XOR_WriteProcessMemory_ccc2 {
  strings:
    $key_ccc2 = { 9b b0 [2] a9 92 [2] af a7 [2] 81 a7 [2] be bb }

  condition:
    any of them
}