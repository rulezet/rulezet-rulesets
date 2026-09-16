rule TTP_XOR_MULT_DOSStub_5630 {
  strings:
    $key_5630 = { 02 58 [2] 76 40 [2] 31 42 [2] 76 53 [2] 38 5f [2] 34 55 [2] 23 5e [2] 38 10 [2] 05 }

  condition:
    any of them
}