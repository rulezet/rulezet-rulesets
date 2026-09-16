rule TTP_XOR_MULT_DOSStub_d668 {
  strings:
    $key_d668 = { 82 00 [2] f6 18 [2] b1 1a [2] f6 0b [2] b8 07 [2] b4 0d [2] a3 06 [2] b8 48 [2] 85 }

  condition:
    any of them
}