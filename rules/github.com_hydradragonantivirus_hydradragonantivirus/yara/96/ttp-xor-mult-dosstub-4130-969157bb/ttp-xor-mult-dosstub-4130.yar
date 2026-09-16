rule TTP_XOR_MULT_DOSStub_4130 {
  strings:
    $key_4130 = { 15 58 [2] 61 40 [2] 26 42 [2] 61 53 [2] 2f 5f [2] 23 55 [2] 34 5e [2] 2f 10 [2] 12 }

  condition:
    any of them
}