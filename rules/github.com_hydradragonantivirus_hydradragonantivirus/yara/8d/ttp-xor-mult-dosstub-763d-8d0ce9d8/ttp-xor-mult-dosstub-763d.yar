rule TTP_XOR_MULT_DOSStub_763d {
  strings:
    $key_763d = { 22 55 [2] 56 4d [2] 11 4f [2] 56 5e [2] 18 52 [2] 14 58 [2] 03 53 [2] 18 1d [2] 25 }

  condition:
    any of them
}