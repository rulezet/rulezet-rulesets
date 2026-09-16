rule TTP_XOR_MULT_DOSStub_d657 {
  strings:
    $key_d657 = { 82 3f [2] f6 27 [2] b1 25 [2] f6 34 [2] b8 38 [2] b4 32 [2] a3 39 [2] b8 77 [2] 85 }

  condition:
    any of them
}