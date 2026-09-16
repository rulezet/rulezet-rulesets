rule TTP_XOR_MULT_DOSStub_d612 {
  strings:
    $key_d612 = { 82 7a [2] f6 62 [2] b1 60 [2] f6 71 [2] b8 7d [2] b4 77 [2] a3 7c [2] b8 32 [2] 85 }

  condition:
    any of them
}