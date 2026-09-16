rule TTP_XOR_MULT_DOSStub_d858 {
  strings:
    $key_d858 = { 8c 30 [2] f8 28 [2] bf 2a [2] f8 3b [2] b6 37 [2] ba 3d [2] ad 36 [2] b6 78 [2] 8b }

  condition:
    any of them
}