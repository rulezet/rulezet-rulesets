rule TTP_XOR_MULT_DOSStub_d708 {
  strings:
    $key_d708 = { 83 60 [2] f7 78 [2] b0 7a [2] f7 6b [2] b9 67 [2] b5 6d [2] a2 66 [2] b9 28 [2] 84 }

  condition:
    any of them
}