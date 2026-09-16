rule TTP_XOR_MULT_DOSStub_7a30 {
  strings:
    $key_7a30 = { 2e 58 [2] 5a 40 [2] 1d 42 [2] 5a 53 [2] 14 5f [2] 18 55 [2] 0f 5e [2] 14 10 [2] 29 }

  condition:
    any of them
}