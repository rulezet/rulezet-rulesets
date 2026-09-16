rule TTP_XOR_MULT_DOSStub_40ba {
  strings:
    $key_40ba = { 14 d2 [2] 60 ca [2] 27 c8 [2] 60 d9 [2] 2e d5 [2] 22 df [2] 35 d4 [2] 2e 9a [2] 13 }

  condition:
    any of them
}