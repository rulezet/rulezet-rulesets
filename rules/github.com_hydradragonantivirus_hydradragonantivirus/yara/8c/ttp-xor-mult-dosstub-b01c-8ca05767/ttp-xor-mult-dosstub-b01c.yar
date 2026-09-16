rule TTP_XOR_MULT_DOSStub_b01c {
  strings:
    $key_b01c = { e4 74 [2] 90 6c [2] d7 6e [2] 90 7f [2] de 73 [2] d2 79 [2] c5 72 [2] de 3c [2] e3 }

  condition:
    any of them
}