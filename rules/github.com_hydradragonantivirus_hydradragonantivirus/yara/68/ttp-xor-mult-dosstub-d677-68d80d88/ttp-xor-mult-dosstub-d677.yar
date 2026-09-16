rule TTP_XOR_MULT_DOSStub_d677 {
  strings:
    $key_d677 = { 82 1f [2] f6 07 [2] b1 05 [2] f6 14 [2] b8 18 [2] b4 12 [2] a3 19 [2] b8 57 [2] 85 }

  condition:
    any of them
}