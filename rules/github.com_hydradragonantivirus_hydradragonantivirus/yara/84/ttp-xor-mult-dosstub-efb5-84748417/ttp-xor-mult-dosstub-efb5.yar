rule TTP_XOR_MULT_DOSStub_efb5 {
  strings:
    $key_efb5 = { bb dd [2] cf c5 [2] 88 c7 [2] cf d6 [2] 81 da [2] 8d d0 [2] 9a db [2] 81 95 [2] bc }

  condition:
    any of them
}