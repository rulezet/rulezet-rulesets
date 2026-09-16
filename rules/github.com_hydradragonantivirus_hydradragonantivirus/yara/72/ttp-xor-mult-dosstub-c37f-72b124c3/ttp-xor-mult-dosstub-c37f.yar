rule TTP_XOR_MULT_DOSStub_c37f {
  strings:
    $key_c37f = { 97 17 [2] e3 0f [2] a4 0d [2] e3 1c [2] ad 10 [2] a1 1a [2] b6 11 [2] ad 5f [2] 90 }

  condition:
    any of them
}