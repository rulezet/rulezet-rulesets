rule TTP_XOR_MULT_DOSStub_b65f {
  strings:
    $key_b65f = { e2 37 [2] 96 2f [2] d1 2d [2] 96 3c [2] d8 30 [2] d4 3a [2] c3 31 [2] d8 7f [2] e5 }

  condition:
    any of them
}