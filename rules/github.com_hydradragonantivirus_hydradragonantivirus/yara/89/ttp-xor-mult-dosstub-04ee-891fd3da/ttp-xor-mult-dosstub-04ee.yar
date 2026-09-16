rule TTP_XOR_MULT_DOSStub_04ee {
  strings:
    $key_04ee = { 50 86 [2] 24 9e [2] 63 9c [2] 24 8d [2] 6a 81 [2] 66 8b [2] 71 80 [2] 6a ce [2] 57 }

  condition:
    any of them
}