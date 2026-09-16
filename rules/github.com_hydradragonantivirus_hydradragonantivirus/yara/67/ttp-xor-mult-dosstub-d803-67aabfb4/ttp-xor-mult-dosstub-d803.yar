rule TTP_XOR_MULT_DOSStub_d803 {
  strings:
    $key_d803 = { 8c 6b [2] f8 73 [2] bf 71 [2] f8 60 [2] b6 6c [2] ba 66 [2] ad 6d [2] b6 23 [2] 8b }

  condition:
    any of them
}