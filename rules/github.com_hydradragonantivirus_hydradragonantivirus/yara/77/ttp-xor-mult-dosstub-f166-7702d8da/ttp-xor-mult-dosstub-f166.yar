rule TTP_XOR_MULT_DOSStub_f166 {
  strings:
    $key_f166 = { a5 0e [2] d1 16 [2] 96 14 [2] d1 05 [2] 9f 09 [2] 93 03 [2] 84 08 [2] 9f 46 [2] a2 }

  condition:
    any of them
}