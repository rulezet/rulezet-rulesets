rule TTP_XOR_MULT_DOSStub_d645 {
  strings:
    $key_d645 = { 82 2d [2] f6 35 [2] b1 37 [2] f6 26 [2] b8 2a [2] b4 20 [2] a3 2b [2] b8 65 [2] 85 }

  condition:
    any of them
}