rule TTP_XOR_MULT_DOSStub_baba {
  strings:
    $key_baba = { ee d2 [2] 9a ca [2] dd c8 [2] 9a d9 [2] d4 d5 [2] d8 df [2] cf d4 [2] d4 9a [2] e9 }

  condition:
    any of them
}