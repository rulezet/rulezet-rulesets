rule TTP_XOR_MULT_DOSStub_b028 {
  strings:
    $key_b028 = { e4 40 [2] 90 58 [2] d7 5a [2] 90 4b [2] de 47 [2] d2 4d [2] c5 46 [2] de 08 [2] e3 }

  condition:
    any of them
}