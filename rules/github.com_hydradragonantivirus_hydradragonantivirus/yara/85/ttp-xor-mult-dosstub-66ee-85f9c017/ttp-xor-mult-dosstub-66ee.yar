rule TTP_XOR_MULT_DOSStub_66ee {
  strings:
    $key_66ee = { 32 86 [2] 46 9e [2] 01 9c [2] 46 8d [2] 08 81 [2] 04 8b [2] 13 80 [2] 08 ce [2] 35 }

  condition:
    any of them
}