rule TTP_XOR_MULT_DOSStub_e0ad {
  strings:
    $key_e0ad = { b4 c5 [2] c0 dd [2] 87 df [2] c0 ce [2] 8e c2 [2] 82 c8 [2] 95 c3 [2] 8e 8d [2] b3 }

  condition:
    any of them
}