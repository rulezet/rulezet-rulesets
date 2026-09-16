rule TTP_XOR_MULT_DOSStub_d635 {
  strings:
    $key_d635 = { 82 5d [2] f6 45 [2] b1 47 [2] f6 56 [2] b8 5a [2] b4 50 [2] a3 5b [2] b8 15 [2] 85 }

  condition:
    any of them
}