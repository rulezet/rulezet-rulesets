rule TTP_XOR_MULT_DOSStub_b04e {
  strings:
    $key_b04e = { e4 26 [2] 90 3e [2] d7 3c [2] 90 2d [2] de 21 [2] d2 2b [2] c5 20 [2] de 6e [2] e3 }

  condition:
    any of them
}