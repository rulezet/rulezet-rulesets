rule TTP_XOR_MULT_DOSStub_70ba {
  strings:
    $key_70ba = { 24 d2 [2] 50 ca [2] 17 c8 [2] 50 d9 [2] 1e d5 [2] 12 df [2] 05 d4 [2] 1e 9a [2] 23 }

  condition:
    any of them
}