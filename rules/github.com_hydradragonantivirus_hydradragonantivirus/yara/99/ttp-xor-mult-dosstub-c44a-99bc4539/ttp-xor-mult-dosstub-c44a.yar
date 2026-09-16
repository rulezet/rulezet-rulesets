rule TTP_XOR_MULT_DOSStub_c44a {
  strings:
    $key_c44a = { 90 22 [2] e4 3a [2] a3 38 [2] e4 29 [2] aa 25 [2] a6 2f [2] b1 24 [2] aa 6a [2] 97 }

  condition:
    any of them
}