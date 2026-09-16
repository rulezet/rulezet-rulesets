rule TTP_XOR_MULT_DOSStub_c33f {
  strings:
    $key_c33f = { 97 57 [2] e3 4f [2] a4 4d [2] e3 5c [2] ad 50 [2] a1 5a [2] b6 51 [2] ad 1f [2] 90 }

  condition:
    any of them
}