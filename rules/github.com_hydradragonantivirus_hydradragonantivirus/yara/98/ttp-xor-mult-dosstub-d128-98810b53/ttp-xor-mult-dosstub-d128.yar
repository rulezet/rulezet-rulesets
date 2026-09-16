rule TTP_XOR_MULT_DOSStub_d128 {
  strings:
    $key_d128 = { 85 40 [2] f1 58 [2] b6 5a [2] f1 4b [2] bf 47 [2] b3 4d [2] a4 46 [2] bf 08 [2] 82 }

  condition:
    any of them
}