rule TTP_XOR_MULT_DOSStub_d8e3 {
  strings:
    $key_d8e3 = { 8c 8b [2] f8 93 [2] bf 91 [2] f8 80 [2] b6 8c [2] ba 86 [2] ad 8d [2] b6 c3 [2] 8b }

  condition:
    any of them
}