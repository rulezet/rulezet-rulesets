rule TTP_XOR_MULT_DOSStub_aead {
  strings:
    $key_aead = { fa c5 [2] 8e dd [2] c9 df [2] 8e ce [2] c0 c2 [2] cc c8 [2] db c3 [2] c0 8d [2] fd }

  condition:
    any of them
}