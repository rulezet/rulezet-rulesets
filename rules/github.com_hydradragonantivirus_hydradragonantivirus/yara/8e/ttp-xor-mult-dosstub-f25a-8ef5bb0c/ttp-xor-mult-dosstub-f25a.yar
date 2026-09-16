rule TTP_XOR_MULT_DOSStub_f25a {
  strings:
    $key_f25a = { a6 32 [2] d2 2a [2] 95 28 [2] d2 39 [2] 9c 35 [2] 90 3f [2] 87 34 [2] 9c 7a [2] a1 }

  condition:
    any of them
}