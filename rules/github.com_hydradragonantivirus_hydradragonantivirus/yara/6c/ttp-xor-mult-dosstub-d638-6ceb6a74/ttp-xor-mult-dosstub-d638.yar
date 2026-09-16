rule TTP_XOR_MULT_DOSStub_d638 {
  strings:
    $key_d638 = { 82 50 [2] f6 48 [2] b1 4a [2] f6 5b [2] b8 57 [2] b4 5d [2] a3 56 [2] b8 18 [2] 85 }

  condition:
    any of them
}