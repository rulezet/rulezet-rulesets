rule TTP_XOR_MULT_DOSStub_6aba {
  strings:
    $key_6aba = { 3e d2 [2] 4a ca [2] 0d c8 [2] 4a d9 [2] 04 d5 [2] 08 df [2] 1f d4 [2] 04 9a [2] 39 }

  condition:
    any of them
}