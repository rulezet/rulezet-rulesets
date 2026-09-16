rule TTP_XOR_MULT_DOSStub_d171 {
  strings:
    $key_d171 = { 85 19 [2] f1 01 [2] b6 03 [2] f1 12 [2] bf 1e [2] b3 14 [2] a4 1f [2] bf 51 [2] 82 }

  condition:
    any of them
}