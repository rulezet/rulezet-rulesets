rule TTP_XOR_MULT_DOSStub_e776 {
  strings:
    $key_e776 = { b3 1e [2] c7 06 [2] 80 04 [2] c7 15 [2] 89 19 [2] 85 13 [2] 92 18 [2] 89 56 [2] b4 }

  condition:
    any of them
}