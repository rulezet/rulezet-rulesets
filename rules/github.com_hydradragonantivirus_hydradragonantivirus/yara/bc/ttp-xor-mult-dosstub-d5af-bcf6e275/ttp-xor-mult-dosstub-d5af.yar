rule TTP_XOR_MULT_DOSStub_d5af {
  strings:
    $key_d5af = { 81 c7 [2] f5 df [2] b2 dd [2] f5 cc [2] bb c0 [2] b7 ca [2] a0 c1 [2] bb 8f [2] 86 }

  condition:
    any of them
}