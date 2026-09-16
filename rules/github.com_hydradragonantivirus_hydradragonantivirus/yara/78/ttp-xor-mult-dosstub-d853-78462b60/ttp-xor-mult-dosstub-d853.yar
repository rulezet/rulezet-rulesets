rule TTP_XOR_MULT_DOSStub_d853 {
  strings:
    $key_d853 = { 8c 3b [2] f8 23 [2] bf 21 [2] f8 30 [2] b6 3c [2] ba 36 [2] ad 3d [2] b6 73 [2] 8b }

  condition:
    any of them
}