rule TTP_XOR_MULT_DOSStub_b023 {
  strings:
    $key_b023 = { e4 4b [2] 90 53 [2] d7 51 [2] 90 40 [2] de 4c [2] d2 46 [2] c5 4d [2] de 03 [2] e3 }

  condition:
    any of them
}