rule TTP_XOR_MULT_DOSStub_d115 {
  strings:
    $key_d115 = { 85 7d [2] f1 65 [2] b6 67 [2] f1 76 [2] bf 7a [2] b3 70 [2] a4 7b [2] bf 35 [2] 82 }

  condition:
    any of them
}