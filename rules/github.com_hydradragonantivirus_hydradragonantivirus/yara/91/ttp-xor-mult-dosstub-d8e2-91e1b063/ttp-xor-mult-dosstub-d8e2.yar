rule TTP_XOR_MULT_DOSStub_d8e2 {
  strings:
    $key_d8e2 = { 8c 8a [2] f8 92 [2] bf 90 [2] f8 81 [2] b6 8d [2] ba 87 [2] ad 8c [2] b6 c2 [2] 8b }

  condition:
    any of them
}