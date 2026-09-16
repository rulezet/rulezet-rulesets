rule TTP_XOR_MULT_DOSStub_effa {
  strings:
    $key_effa = { bb 92 [2] cf 8a [2] 88 88 [2] cf 99 [2] 81 95 [2] 8d 9f [2] 9a 94 [2] 81 da [2] bc }

  condition:
    any of them
}