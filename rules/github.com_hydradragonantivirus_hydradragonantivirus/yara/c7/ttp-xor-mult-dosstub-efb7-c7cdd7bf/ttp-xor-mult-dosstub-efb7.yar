rule TTP_XOR_MULT_DOSStub_efb7 {
  strings:
    $key_efb7 = { bb df [2] cf c7 [2] 88 c5 [2] cf d4 [2] 81 d8 [2] 8d d2 [2] 9a d9 [2] 81 97 [2] bc }

  condition:
    any of them
}