rule TTP_XOR_MULT_DOSStub_efb1 {
  strings:
    $key_efb1 = { bb d9 [2] cf c1 [2] 88 c3 [2] cf d2 [2] 81 de [2] 8d d4 [2] 9a df [2] 81 91 [2] bc }

  condition:
    any of them
}