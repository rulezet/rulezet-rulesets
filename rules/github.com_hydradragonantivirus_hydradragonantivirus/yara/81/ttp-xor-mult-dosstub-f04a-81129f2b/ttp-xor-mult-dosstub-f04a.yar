rule TTP_XOR_MULT_DOSStub_f04a {
  strings:
    $key_f04a = { a4 22 [2] d0 3a [2] 97 38 [2] d0 29 [2] 9e 25 [2] 92 2f [2] 85 24 [2] 9e 6a [2] a3 }

  condition:
    any of them
}