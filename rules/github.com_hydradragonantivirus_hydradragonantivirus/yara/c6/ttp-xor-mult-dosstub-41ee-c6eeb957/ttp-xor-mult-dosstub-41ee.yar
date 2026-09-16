rule TTP_XOR_MULT_DOSStub_41ee {
  strings:
    $key_41ee = { 15 86 [2] 61 9e [2] 26 9c [2] 61 8d [2] 2f 81 [2] 23 8b [2] 34 80 [2] 2f ce [2] 12 }

  condition:
    any of them
}