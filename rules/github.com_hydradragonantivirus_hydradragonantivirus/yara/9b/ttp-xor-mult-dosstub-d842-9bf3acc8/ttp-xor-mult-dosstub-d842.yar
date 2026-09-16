rule TTP_XOR_MULT_DOSStub_d842 {
  strings:
    $key_d842 = { 8c 2a [2] f8 32 [2] bf 30 [2] f8 21 [2] b6 2d [2] ba 27 [2] ad 2c [2] b6 62 [2] 8b }

  condition:
    any of them
}