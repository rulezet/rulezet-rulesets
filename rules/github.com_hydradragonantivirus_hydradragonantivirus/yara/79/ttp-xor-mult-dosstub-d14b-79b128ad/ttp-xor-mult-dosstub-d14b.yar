rule TTP_XOR_MULT_DOSStub_d14b {
  strings:
    $key_d14b = { 85 23 [2] f1 3b [2] b6 39 [2] f1 28 [2] bf 24 [2] b3 2e [2] a4 25 [2] bf 6b [2] 82 }

  condition:
    any of them
}