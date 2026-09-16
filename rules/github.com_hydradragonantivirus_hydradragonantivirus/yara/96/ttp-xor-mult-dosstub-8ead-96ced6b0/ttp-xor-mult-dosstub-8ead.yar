rule TTP_XOR_MULT_DOSStub_8ead {
  strings:
    $key_8ead = { da c5 [2] ae dd [2] e9 df [2] ae ce [2] e0 c2 [2] ec c8 [2] fb c3 [2] e0 8d [2] dd }

  condition:
    any of them
}