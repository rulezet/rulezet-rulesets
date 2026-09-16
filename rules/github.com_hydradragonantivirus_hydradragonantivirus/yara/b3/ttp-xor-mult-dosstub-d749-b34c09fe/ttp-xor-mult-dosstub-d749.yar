rule TTP_XOR_MULT_DOSStub_d749 {
  strings:
    $key_d749 = { 83 21 [2] f7 39 [2] b0 3b [2] f7 2a [2] b9 26 [2] b5 2c [2] a2 27 [2] b9 69 [2] 84 }

  condition:
    any of them
}