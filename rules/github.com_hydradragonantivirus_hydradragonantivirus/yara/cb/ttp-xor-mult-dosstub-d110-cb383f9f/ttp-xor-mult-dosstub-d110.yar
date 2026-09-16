rule TTP_XOR_MULT_DOSStub_d110 {
  strings:
    $key_d110 = { 85 78 [2] f1 60 [2] b6 62 [2] f1 73 [2] bf 7f [2] b3 75 [2] a4 7e [2] bf 30 [2] 82 }

  condition:
    any of them
}