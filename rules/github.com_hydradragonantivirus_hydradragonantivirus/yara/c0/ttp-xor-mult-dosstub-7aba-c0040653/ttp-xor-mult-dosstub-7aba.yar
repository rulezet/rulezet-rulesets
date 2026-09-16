rule TTP_XOR_MULT_DOSStub_7aba {
  strings:
    $key_7aba = { 2e d2 [2] 5a ca [2] 1d c8 [2] 5a d9 [2] 14 d5 [2] 18 df [2] 0f d4 [2] 14 9a [2] 29 }

  condition:
    any of them
}