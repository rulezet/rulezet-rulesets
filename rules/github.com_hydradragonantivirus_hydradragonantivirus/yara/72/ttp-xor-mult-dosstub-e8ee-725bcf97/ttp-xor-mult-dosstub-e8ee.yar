rule TTP_XOR_MULT_DOSStub_e8ee {
  strings:
    $key_e8ee = { bc 86 [2] c8 9e [2] 8f 9c [2] c8 8d [2] 86 81 [2] 8a 8b [2] 9d 80 [2] 86 ce [2] bb }

  condition:
    any of them
}