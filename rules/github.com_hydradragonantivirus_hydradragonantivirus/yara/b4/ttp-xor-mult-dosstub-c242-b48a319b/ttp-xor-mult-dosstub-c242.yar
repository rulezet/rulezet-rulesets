rule TTP_XOR_MULT_DOSStub_c242 {
  strings:
    $key_c242 = { 96 2a [2] e2 32 [2] a5 30 [2] e2 21 [2] ac 2d [2] a0 27 [2] b7 2c [2] ac 62 [2] 91 }

  condition:
    any of them
}