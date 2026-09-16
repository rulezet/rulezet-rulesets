rule TTP_XOR_MULT_DOSStub_d6f8 {
  strings:
    $key_d6f8 = { 82 90 [2] f6 88 [2] b1 8a [2] f6 9b [2] b8 97 [2] b4 9d [2] a3 96 [2] b8 d8 [2] 85 }

  condition:
    any of them
}