rule TTP_XOR_MULT_DOSStub_49ee {
  strings:
    $key_49ee = { 1d 86 [2] 69 9e [2] 2e 9c [2] 69 8d [2] 27 81 [2] 2b 8b [2] 3c 80 [2] 27 ce [2] 1a }

  condition:
    any of them
}