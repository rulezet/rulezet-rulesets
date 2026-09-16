rule TTP_XOR_MULT_DOSStub_d669 {
  strings:
    $key_d669 = { 82 01 [2] f6 19 [2] b1 1b [2] f6 0a [2] b8 06 [2] b4 0c [2] a3 07 [2] b8 49 [2] 85 }

  condition:
    any of them
}