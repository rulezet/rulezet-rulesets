rule TTP_XOR_MULT_DOSStub_e1af {
  strings:
    $key_e1af = { b5 c7 [2] c1 df [2] 86 dd [2] c1 cc [2] 8f c0 [2] 83 ca [2] 94 c1 [2] 8f 8f [2] b2 }

  condition:
    any of them
}