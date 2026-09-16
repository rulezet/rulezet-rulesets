rule TTP_XOR_MULT_DOSStub_f466 {
  strings:
    $key_f466 = { a0 0e [2] d4 16 [2] 93 14 [2] d4 05 [2] 9a 09 [2] 96 03 [2] 81 08 [2] 9a 46 [2] a7 }

  condition:
    any of them
}