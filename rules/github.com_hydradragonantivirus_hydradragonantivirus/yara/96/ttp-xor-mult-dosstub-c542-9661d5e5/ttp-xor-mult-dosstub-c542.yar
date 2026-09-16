rule TTP_XOR_MULT_DOSStub_c542 {
  strings:
    $key_c542 = { 91 2a [2] e5 32 [2] a2 30 [2] e5 21 [2] ab 2d [2] a7 27 [2] b0 2c [2] ab 62 [2] 96 }

  condition:
    any of them
}