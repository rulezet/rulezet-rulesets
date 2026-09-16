rule TTP_XOR_MULT_DOSStub_efb9 {
  strings:
    $key_efb9 = { bb d1 [2] cf c9 [2] 88 cb [2] cf da [2] 81 d6 [2] 8d dc [2] 9a d7 [2] 81 99 [2] bc }

  condition:
    any of them
}