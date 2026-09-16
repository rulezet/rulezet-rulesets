rule TTP_XOR_MULT_DOSStub_b01e {
  strings:
    $key_b01e = { e4 76 [2] 90 6e [2] d7 6c [2] 90 7d [2] de 71 [2] d2 7b [2] c5 70 [2] de 3e [2] e3 }

  condition:
    any of them
}