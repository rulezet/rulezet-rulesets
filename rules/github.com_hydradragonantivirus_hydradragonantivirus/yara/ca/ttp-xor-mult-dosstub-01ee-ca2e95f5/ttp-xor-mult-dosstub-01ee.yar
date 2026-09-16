rule TTP_XOR_MULT_DOSStub_01ee {
  strings:
    $key_01ee = { 55 86 [2] 21 9e [2] 66 9c [2] 21 8d [2] 6f 81 [2] 63 8b [2] 74 80 [2] 6f ce [2] 52 }

  condition:
    any of them
}