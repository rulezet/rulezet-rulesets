rule TTP_XOR_MULT_DOSStub_d619 {
  strings:
    $key_d619 = { 82 71 [2] f6 69 [2] b1 6b [2] f6 7a [2] b8 76 [2] b4 7c [2] a3 77 [2] b8 39 [2] 85 }

  condition:
    any of them
}