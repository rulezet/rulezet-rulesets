rule TTP_XOR_MULT_DOSStub_d605 {
  strings:
    $key_d605 = { 82 6d [2] f6 75 [2] b1 77 [2] f6 66 [2] b8 6a [2] b4 60 [2] a3 6b [2] b8 25 [2] 85 }

  condition:
    any of them
}