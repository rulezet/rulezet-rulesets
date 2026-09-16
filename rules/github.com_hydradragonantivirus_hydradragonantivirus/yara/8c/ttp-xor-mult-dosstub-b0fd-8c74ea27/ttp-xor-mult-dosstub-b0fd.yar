rule TTP_XOR_MULT_DOSStub_b0fd {
  strings:
    $key_b0fd = { e4 95 [2] 90 8d [2] d7 8f [2] 90 9e [2] de 92 [2] d2 98 [2] c5 93 [2] de dd [2] e3 }

  condition:
    any of them
}