rule TTP_XOR_MULT_DOSStub_f24a {
  strings:
    $key_f24a = { a6 22 [2] d2 3a [2] 95 38 [2] d2 29 [2] 9c 25 [2] 90 2f [2] 87 24 [2] 9c 6a [2] a1 }

  condition:
    any of them
}