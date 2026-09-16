rule TTP_XOR_MULT_DOSStub_2aba {
  strings:
    $key_2aba = { 7e d2 [2] 0a ca [2] 4d c8 [2] 0a d9 [2] 44 d5 [2] 48 df [2] 5f d4 [2] 44 9a [2] 79 }

  condition:
    any of them
}