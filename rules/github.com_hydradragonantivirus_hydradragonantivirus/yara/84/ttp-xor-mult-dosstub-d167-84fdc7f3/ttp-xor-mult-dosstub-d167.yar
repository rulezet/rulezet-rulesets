rule TTP_XOR_MULT_DOSStub_d167 {
  strings:
    $key_d167 = { 85 0f [2] f1 17 [2] b6 15 [2] f1 04 [2] bf 08 [2] b3 02 [2] a4 09 [2] bf 47 [2] 82 }

  condition:
    any of them
}