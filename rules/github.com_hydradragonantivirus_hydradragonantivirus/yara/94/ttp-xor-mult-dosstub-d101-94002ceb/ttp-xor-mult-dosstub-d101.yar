rule TTP_XOR_MULT_DOSStub_d101 {
  strings:
    $key_d101 = { 85 69 [2] f1 71 [2] b6 73 [2] f1 62 [2] bf 6e [2] b3 64 [2] a4 6f [2] bf 21 [2] 82 }

  condition:
    any of them
}