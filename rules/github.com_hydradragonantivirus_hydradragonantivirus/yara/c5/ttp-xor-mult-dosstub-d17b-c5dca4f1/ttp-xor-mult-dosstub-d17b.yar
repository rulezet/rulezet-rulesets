rule TTP_XOR_MULT_DOSStub_d17b {
  strings:
    $key_d17b = { 85 13 [2] f1 0b [2] b6 09 [2] f1 18 [2] bf 14 [2] b3 1e [2] a4 15 [2] bf 5b [2] 82 }

  condition:
    any of them
}