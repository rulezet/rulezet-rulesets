rule TTP_XOR_MULT_DOSStub_e5ad {
  strings:
    $key_e5ad = { b1 c5 [2] c5 dd [2] 82 df [2] c5 ce [2] 8b c2 [2] 87 c8 [2] 90 c3 [2] 8b 8d [2] b6 }

  condition:
    any of them
}