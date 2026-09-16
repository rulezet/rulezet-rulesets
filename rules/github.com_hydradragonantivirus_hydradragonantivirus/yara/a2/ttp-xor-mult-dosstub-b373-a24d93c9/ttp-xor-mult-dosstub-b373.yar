rule TTP_XOR_MULT_DOSStub_b373 {
  strings:
    $key_b373 = { e7 1b [2] 93 03 [2] d4 01 [2] 93 10 [2] dd 1c [2] d1 16 [2] c6 1d [2] dd 53 [2] e0 }

  condition:
    any of them
}