rule TTP_XOR_MULT_DOSStub_73ee {
  strings:
    $key_73ee = { 27 86 [2] 53 9e [2] 14 9c [2] 53 8d [2] 1d 81 [2] 11 8b [2] 06 80 [2] 1d ce [2] 20 }

  condition:
    any of them
}