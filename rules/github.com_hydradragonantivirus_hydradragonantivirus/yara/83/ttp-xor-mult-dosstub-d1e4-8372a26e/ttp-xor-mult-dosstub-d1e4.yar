rule TTP_XOR_MULT_DOSStub_d1e4 {
  strings:
    $key_d1e4 = { 85 8c [2] f1 94 [2] b6 96 [2] f1 87 [2] bf 8b [2] b3 81 [2] a4 8a [2] bf c4 [2] 82 }

  condition:
    any of them
}