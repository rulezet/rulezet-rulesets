rule TTP_XOR_MULT_DOSStub_d627 {
  strings:
    $key_d627 = { 82 4f [2] f6 57 [2] b1 55 [2] f6 44 [2] b8 48 [2] b4 42 [2] a3 49 [2] b8 07 [2] 85 }

  condition:
    any of them
}