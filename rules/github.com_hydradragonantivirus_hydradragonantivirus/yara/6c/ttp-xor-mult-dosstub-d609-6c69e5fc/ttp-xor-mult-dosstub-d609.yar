rule TTP_XOR_MULT_DOSStub_d609 {
  strings:
    $key_d609 = { 82 61 [2] f6 79 [2] b1 7b [2] f6 6a [2] b8 66 [2] b4 6c [2] a3 67 [2] b8 29 [2] 85 }

  condition:
    any of them
}