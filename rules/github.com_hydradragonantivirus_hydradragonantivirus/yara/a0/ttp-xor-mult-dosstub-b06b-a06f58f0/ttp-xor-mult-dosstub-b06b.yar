rule TTP_XOR_MULT_DOSStub_b06b {
  strings:
    $key_b06b = { e4 03 [2] 90 1b [2] d7 19 [2] 90 08 [2] de 04 [2] d2 0e [2] c5 05 [2] de 4b [2] e3 }

  condition:
    any of them
}