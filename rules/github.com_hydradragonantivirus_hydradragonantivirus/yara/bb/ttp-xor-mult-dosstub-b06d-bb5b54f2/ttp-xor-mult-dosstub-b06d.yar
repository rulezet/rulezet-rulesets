rule TTP_XOR_MULT_DOSStub_b06d {
  strings:
    $key_b06d = { e4 05 [2] 90 1d [2] d7 1f [2] 90 0e [2] de 02 [2] d2 08 [2] c5 03 [2] de 4d [2] e3 }

  condition:
    any of them
}