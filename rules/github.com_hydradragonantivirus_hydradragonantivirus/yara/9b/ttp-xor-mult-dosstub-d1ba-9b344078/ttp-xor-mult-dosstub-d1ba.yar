rule TTP_XOR_MULT_DOSStub_d1ba {
  strings:
    $key_d1ba = { 85 d2 [2] f1 ca [2] b6 c8 [2] f1 d9 [2] bf d5 [2] b3 df [2] a4 d4 [2] bf 9a [2] 82 }

  condition:
    any of them
}