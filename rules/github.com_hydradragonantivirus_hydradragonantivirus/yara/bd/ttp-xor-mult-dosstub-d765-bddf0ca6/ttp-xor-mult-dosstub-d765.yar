rule TTP_XOR_MULT_DOSStub_d765 {
  strings:
    $key_d765 = { 83 0d [2] f7 15 [2] b0 17 [2] f7 06 [2] b9 0a [2] b5 00 [2] a2 0b [2] b9 45 [2] 84 }

  condition:
    any of them
}