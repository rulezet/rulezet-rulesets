rule TTP_XOR_MULT_DOSStub_75ee {
  strings:
    $key_75ee = { 21 86 [2] 55 9e [2] 12 9c [2] 55 8d [2] 1b 81 [2] 17 8b [2] 00 80 [2] 1b ce [2] 26 }

  condition:
    any of them
}