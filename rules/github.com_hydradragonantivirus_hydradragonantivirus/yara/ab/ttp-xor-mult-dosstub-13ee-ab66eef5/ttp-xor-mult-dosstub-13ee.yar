rule TTP_XOR_MULT_DOSStub_13ee {
  strings:
    $key_13ee = { 47 86 [2] 33 9e [2] 74 9c [2] 33 8d [2] 7d 81 [2] 71 8b [2] 66 80 [2] 7d ce [2] 40 }

  condition:
    any of them
}