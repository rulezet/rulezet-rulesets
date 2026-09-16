rule TTP_XOR_MULT_DOSStub_d113 {
  strings:
    $key_d113 = { 85 7b [2] f1 63 [2] b6 61 [2] f1 70 [2] bf 7c [2] b3 76 [2] a4 7d [2] bf 33 [2] 82 }

  condition:
    any of them
}