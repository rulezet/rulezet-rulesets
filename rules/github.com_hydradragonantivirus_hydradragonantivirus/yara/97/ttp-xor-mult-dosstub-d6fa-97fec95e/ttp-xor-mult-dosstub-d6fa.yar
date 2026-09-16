rule TTP_XOR_MULT_DOSStub_d6fa {
  strings:
    $key_d6fa = { 82 92 [2] f6 8a [2] b1 88 [2] f6 99 [2] b8 95 [2] b4 9f [2] a3 94 [2] b8 da [2] 85 }

  condition:
    any of them
}