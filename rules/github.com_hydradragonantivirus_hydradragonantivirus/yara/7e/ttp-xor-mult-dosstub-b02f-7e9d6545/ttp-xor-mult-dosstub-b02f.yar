rule TTP_XOR_MULT_DOSStub_b02f {
  strings:
    $key_b02f = { e4 47 [2] 90 5f [2] d7 5d [2] 90 4c [2] de 40 [2] d2 4a [2] c5 41 [2] de 0f [2] e3 }

  condition:
    any of them
}