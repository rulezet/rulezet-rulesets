rule TTP_XOR_MULT_DOSStub_d1af {
  strings:
    $key_d1af = { 85 c7 [2] f1 df [2] b6 dd [2] f1 cc [2] bf c0 [2] b3 ca [2] a4 c1 [2] bf 8f [2] 82 }

  condition:
    any of them
}