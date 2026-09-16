rule TTP_XOR_MULT_DOSStub_f55a {
  strings:
    $key_f55a = { a1 32 [2] d5 2a [2] 92 28 [2] d5 39 [2] 9b 35 [2] 97 3f [2] 80 34 [2] 9b 7a [2] a6 }

  condition:
    any of them
}