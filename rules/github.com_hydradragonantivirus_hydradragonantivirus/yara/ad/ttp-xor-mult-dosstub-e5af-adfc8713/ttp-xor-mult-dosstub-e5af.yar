rule TTP_XOR_MULT_DOSStub_e5af {
  strings:
    $key_e5af = { b1 c7 [2] c5 df [2] 82 dd [2] c5 cc [2] 8b c0 [2] 87 ca [2] 90 c1 [2] 8b 8f [2] b6 }

  condition:
    any of them
}