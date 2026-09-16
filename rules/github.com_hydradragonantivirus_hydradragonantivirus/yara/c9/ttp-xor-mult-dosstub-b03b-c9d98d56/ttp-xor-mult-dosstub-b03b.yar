rule TTP_XOR_MULT_DOSStub_b03b {
  strings:
    $key_b03b = { e4 53 [2] 90 4b [2] d7 49 [2] 90 58 [2] de 54 [2] d2 5e [2] c5 55 [2] de 1b [2] e3 }

  condition:
    any of them
}