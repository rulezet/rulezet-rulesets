rule TTP_XOR_MULT_DOSStub_b02e {
  strings:
    $key_b02e = { e4 46 [2] 90 5e [2] d7 5c [2] 90 4d [2] de 41 [2] d2 4b [2] c5 40 [2] de 0e [2] e3 }

  condition:
    any of them
}