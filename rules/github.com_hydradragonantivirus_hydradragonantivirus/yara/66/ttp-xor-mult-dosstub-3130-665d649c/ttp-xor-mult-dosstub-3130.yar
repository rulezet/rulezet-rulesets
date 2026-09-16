rule TTP_XOR_MULT_DOSStub_3130 {
  strings:
    $key_3130 = { 65 58 [2] 11 40 [2] 56 42 [2] 11 53 [2] 5f 5f [2] 53 55 [2] 44 5e [2] 5f 10 [2] 62 }

  condition:
    any of them
}