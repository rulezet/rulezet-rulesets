rule TTP_XOR_MULT_DOSStub_d622 {
  strings:
    $key_d622 = { 82 4a [2] f6 52 [2] b1 50 [2] f6 41 [2] b8 4d [2] b4 47 [2] a3 4c [2] b8 02 [2] 85 }

  condition:
    any of them
}