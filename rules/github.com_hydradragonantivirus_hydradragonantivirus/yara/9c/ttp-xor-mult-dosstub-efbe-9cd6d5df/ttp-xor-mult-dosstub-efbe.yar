rule TTP_XOR_MULT_DOSStub_efbe {
  strings:
    $key_efbe = { bb d6 [2] cf ce [2] 88 cc [2] cf dd [2] 81 d1 [2] 8d db [2] 9a d0 [2] 81 9e [2] bc }

  condition:
    any of them
}