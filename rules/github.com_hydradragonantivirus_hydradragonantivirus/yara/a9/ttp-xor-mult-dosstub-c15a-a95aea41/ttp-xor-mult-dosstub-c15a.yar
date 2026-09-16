rule TTP_XOR_MULT_DOSStub_c15a {
  strings:
    $key_c15a = { 95 32 [2] e1 2a [2] a6 28 [2] e1 39 [2] af 35 [2] a3 3f [2] b4 34 [2] af 7a [2] 92 }

  condition:
    any of them
}