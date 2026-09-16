rule TTP_XOR_MULT_DOSStub_effc {
  strings:
    $key_effc = { bb 94 [2] cf 8c [2] 88 8e [2] cf 9f [2] 81 93 [2] 8d 99 [2] 9a 92 [2] 81 dc [2] bc }

  condition:
    any of them
}