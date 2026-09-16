rule TTP_XOR_MULT_DOSStub_54ee {
  strings:
    $key_54ee = { 00 86 [2] 74 9e [2] 33 9c [2] 74 8d [2] 3a 81 [2] 36 8b [2] 21 80 [2] 3a ce [2] 07 }

  condition:
    any of them
}