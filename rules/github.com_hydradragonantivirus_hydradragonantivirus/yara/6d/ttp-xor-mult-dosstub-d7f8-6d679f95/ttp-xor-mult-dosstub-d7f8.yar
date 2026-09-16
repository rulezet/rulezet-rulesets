rule TTP_XOR_MULT_DOSStub_d7f8 {
  strings:
    $key_d7f8 = { 83 90 [2] f7 88 [2] b0 8a [2] f7 9b [2] b9 97 [2] b5 9d [2] a2 96 [2] b9 d8 [2] 84 }

  condition:
    any of them
}