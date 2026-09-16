rule TTP_XOR_MULT_DOSStub_7730 {
  strings:
    $key_7730 = { 23 58 [2] 57 40 [2] 10 42 [2] 57 53 [2] 19 5f [2] 15 55 [2] 02 5e [2] 19 10 [2] 24 }

  condition:
    any of them
}