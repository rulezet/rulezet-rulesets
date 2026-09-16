rule TTP_XOR_MULT_DOSStub_c67a {
  strings:
    $key_c67a = { 92 12 [2] e6 0a [2] a1 08 [2] e6 19 [2] a8 15 [2] a4 1f [2] b3 14 [2] a8 5a [2] 95 }

  condition:
    any of them
}