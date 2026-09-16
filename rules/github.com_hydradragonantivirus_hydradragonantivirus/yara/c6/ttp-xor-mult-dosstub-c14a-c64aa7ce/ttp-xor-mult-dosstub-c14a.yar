rule TTP_XOR_MULT_DOSStub_c14a {
  strings:
    $key_c14a = { 95 22 [2] e1 3a [2] a6 38 [2] e1 29 [2] af 25 [2] a3 2f [2] b4 24 [2] af 6a [2] 92 }

  condition:
    any of them
}