rule TTP_XOR_MULT_DOSStub_b03f {
  strings:
    $key_b03f = { e4 57 [2] 90 4f [2] d7 4d [2] 90 5c [2] de 50 [2] d2 5a [2] c5 51 [2] de 1f [2] e3 }

  condition:
    any of them
}