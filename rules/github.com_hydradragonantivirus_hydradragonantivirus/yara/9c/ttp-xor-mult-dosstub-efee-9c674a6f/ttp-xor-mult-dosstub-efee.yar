rule TTP_XOR_MULT_DOSStub_efee {
  strings:
    $key_efee = { bb 86 [2] cf 9e [2] 88 9c [2] cf 8d [2] 81 81 [2] 8d 8b [2] 9a 80 [2] 81 ce [2] bc }

  condition:
    any of them
}