rule TTP_XOR_MULT_DOSStub_14ee {
  strings:
    $key_14ee = { 40 86 [2] 34 9e [2] 73 9c [2] 34 8d [2] 7a 81 [2] 76 8b [2] 61 80 [2] 7a ce [2] 47 }

  condition:
    any of them
}