rule TTP_XOR_MULT_DOSStub_b5ad {
  strings:
    $key_b5ad = { e1 c5 [2] 95 dd [2] d2 df [2] 95 ce [2] db c2 [2] d7 c8 [2] c0 c3 [2] db 8d [2] e6 }

  condition:
    any of them
}