rule TTP_XOR_MULT_DOSStub_18a4 {
  strings:
    $key_18a4 = { 4c cc [2] 38 d4 [2] 7f d6 [2] 38 c7 [2] 76 cb [2] 7a c1 [2] 6d ca [2] 76 84 [2] 4b }

  condition:
    any of them
}