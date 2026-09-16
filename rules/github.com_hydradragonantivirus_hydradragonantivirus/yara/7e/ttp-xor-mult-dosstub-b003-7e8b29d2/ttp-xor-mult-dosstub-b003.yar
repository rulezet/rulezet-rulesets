rule TTP_XOR_MULT_DOSStub_b003 {
  strings:
    $key_b003 = { e4 6b [2] 90 73 [2] d7 71 [2] 90 60 [2] de 6c [2] d2 66 [2] c5 6d [2] de 23 [2] e3 }

  condition:
    any of them
}