rule TTP_XOR_MULT_DOSStub_2776 {
  strings:
    $key_2776 = { 73 1e [2] 07 06 [2] 40 04 [2] 07 15 [2] 49 19 [2] 45 13 [2] 52 18 [2] 49 56 [2] 74 }

  condition:
    any of them
}