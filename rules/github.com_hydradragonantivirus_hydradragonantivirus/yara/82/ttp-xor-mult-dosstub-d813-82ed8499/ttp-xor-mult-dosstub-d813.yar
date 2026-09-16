rule TTP_XOR_MULT_DOSStub_d813 {
  strings:
    $key_d813 = { 8c 7b [2] f8 63 [2] bf 61 [2] f8 70 [2] b6 7c [2] ba 76 [2] ad 7d [2] b6 33 [2] 8b }

  condition:
    any of them
}