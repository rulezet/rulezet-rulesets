rule TTP_XOR_MULT_DOSStub_faba {
  strings:
    $key_faba = { ae d2 [2] da ca [2] 9d c8 [2] da d9 [2] 94 d5 [2] 98 df [2] 8f d4 [2] 94 9a [2] a9 }

  condition:
    any of them
}