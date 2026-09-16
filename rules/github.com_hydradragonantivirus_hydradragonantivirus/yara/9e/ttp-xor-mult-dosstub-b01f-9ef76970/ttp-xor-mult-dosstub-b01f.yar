rule TTP_XOR_MULT_DOSStub_b01f {
  strings:
    $key_b01f = { e4 77 [2] 90 6f [2] d7 6d [2] 90 7c [2] de 70 [2] d2 7a [2] c5 71 [2] de 3f [2] e3 }

  condition:
    any of them
}