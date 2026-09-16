rule TTP_XOR_MULT_DOSStub_f00a {
  strings:
    $key_f00a = { a4 62 [2] d0 7a [2] 97 78 [2] d0 69 [2] 9e 65 [2] 92 6f [2] 85 64 [2] 9e 2a [2] a3 }

  condition:
    any of them
}