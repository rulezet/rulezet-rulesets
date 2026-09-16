rule TTP_XOR_MULT_DOSStub_d124 {
  strings:
    $key_d124 = { 85 4c [2] f1 54 [2] b6 56 [2] f1 47 [2] bf 4b [2] b3 41 [2] a4 4a [2] bf 04 [2] 82 }

  condition:
    any of them
}