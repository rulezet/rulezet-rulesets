rule TTP_XOR_MULT_DOSStub_62ee {
  strings:
    $key_62ee = { 36 86 [2] 42 9e [2] 05 9c [2] 42 8d [2] 0c 81 [2] 00 8b [2] 17 80 [2] 0c ce [2] 31 }

  condition:
    any of them
}