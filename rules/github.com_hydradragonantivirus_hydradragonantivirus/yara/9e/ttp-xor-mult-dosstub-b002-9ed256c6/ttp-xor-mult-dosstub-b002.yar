rule TTP_XOR_MULT_DOSStub_b002 {
  strings:
    $key_b002 = { e4 6a [2] 90 72 [2] d7 70 [2] 90 61 [2] de 6d [2] d2 67 [2] c5 6c [2] de 22 [2] e3 }

  condition:
    any of them
}