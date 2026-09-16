rule TTP_XOR_MULT_DOSStub_e6af {
  strings:
    $key_e6af = { b2 c7 [2] c6 df [2] 81 dd [2] c6 cc [2] 88 c0 [2] 84 ca [2] 93 c1 [2] 88 8f [2] b5 }

  condition:
    any of them
}