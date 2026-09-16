rule TTP_XOR_MULT_DOSStub_d107 {
  strings:
    $key_d107 = { 85 6f [2] f1 77 [2] b6 75 [2] f1 64 [2] bf 68 [2] b3 62 [2] a4 69 [2] bf 27 [2] 82 }

  condition:
    any of them
}