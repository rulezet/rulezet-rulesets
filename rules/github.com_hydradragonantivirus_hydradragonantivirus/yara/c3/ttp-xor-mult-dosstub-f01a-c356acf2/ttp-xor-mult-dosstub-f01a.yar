rule TTP_XOR_MULT_DOSStub_f01a {
  strings:
    $key_f01a = { a4 72 [2] d0 6a [2] 97 68 [2] d0 79 [2] 9e 75 [2] 92 7f [2] 85 74 [2] 9e 3a [2] a3 }

  condition:
    any of them
}