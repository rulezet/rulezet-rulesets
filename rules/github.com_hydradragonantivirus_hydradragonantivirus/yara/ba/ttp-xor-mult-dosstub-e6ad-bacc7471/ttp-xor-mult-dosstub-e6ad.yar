rule TTP_XOR_MULT_DOSStub_e6ad {
  strings:
    $key_e6ad = { b2 c5 [2] c6 dd [2] 81 df [2] c6 ce [2] 88 c2 [2] 84 c8 [2] 93 c3 [2] 88 8d [2] b5 }

  condition:
    any of them
}