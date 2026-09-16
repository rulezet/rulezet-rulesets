rule TTP_XOR_MULT_DOSStub_d614 {
  strings:
    $key_d614 = { 82 7c [2] f6 64 [2] b1 66 [2] f6 77 [2] b8 7b [2] b4 71 [2] a3 7a [2] b8 34 [2] 85 }

  condition:
    any of them
}