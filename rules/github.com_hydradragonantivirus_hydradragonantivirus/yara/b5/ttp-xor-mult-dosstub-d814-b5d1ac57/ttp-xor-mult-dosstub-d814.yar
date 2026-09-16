rule TTP_XOR_MULT_DOSStub_d814 {
  strings:
    $key_d814 = { 8c 7c [2] f8 64 [2] bf 66 [2] f8 77 [2] b6 7b [2] ba 71 [2] ad 7a [2] b6 34 [2] 8b }

  condition:
    any of them
}