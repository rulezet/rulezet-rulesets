rule TTP_XOR_MULT_DOSStub_c244 {
  strings:
    $key_c244 = { 96 2c [2] e2 34 [2] a5 36 [2] e2 27 [2] ac 2b [2] a0 21 [2] b7 2a [2] ac 64 [2] 91 }

  condition:
    any of them
}