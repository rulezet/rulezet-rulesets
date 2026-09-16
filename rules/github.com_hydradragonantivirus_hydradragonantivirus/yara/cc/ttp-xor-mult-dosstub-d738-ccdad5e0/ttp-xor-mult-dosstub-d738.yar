rule TTP_XOR_MULT_DOSStub_d738 {
  strings:
    $key_d738 = { 83 50 [2] f7 48 [2] b0 4a [2] f7 5b [2] b9 57 [2] b5 5d [2] a2 56 [2] b9 18 [2] 84 }

  condition:
    any of them
}