rule TTP_XOR_MULT_DOSStub_aeaf {
  strings:
    $key_aeaf = { fa c7 [2] 8e df [2] c9 dd [2] 8e cc [2] c0 c0 [2] cc ca [2] db c1 [2] c0 8f [2] fd }

  condition:
    any of them
}