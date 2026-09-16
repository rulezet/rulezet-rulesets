rule TTP_XOR_MULT_DOSStub_fbba {
  strings:
    $key_fbba = { af d2 [2] db ca [2] 9c c8 [2] db d9 [2] 95 d5 [2] 99 df [2] 8e d4 [2] 95 9a [2] a8 }

  condition:
    any of them
}