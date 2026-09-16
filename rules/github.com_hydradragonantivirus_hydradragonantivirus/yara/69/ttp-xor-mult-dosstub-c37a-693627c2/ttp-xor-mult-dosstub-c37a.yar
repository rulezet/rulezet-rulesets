rule TTP_XOR_MULT_DOSStub_c37a {
  strings:
    $key_c37a = { 97 12 [2] e3 0a [2] a4 08 [2] e3 19 [2] ad 15 [2] a1 1f [2] b6 14 [2] ad 5a [2] 90 }

  condition:
    any of them
}