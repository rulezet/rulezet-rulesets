rule TTP_XOR_MULT_DOSStub_1aba {
  strings:
    $key_1aba = { 4e d2 [2] 3a ca [2] 7d c8 [2] 3a d9 [2] 74 d5 [2] 78 df [2] 6f d4 [2] 74 9a [2] 49 }

  condition:
    any of them
}