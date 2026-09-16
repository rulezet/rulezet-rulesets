rule TTP_XOR_MULT_DOSStub_51ee {
  strings:
    $key_51ee = { 05 86 [2] 71 9e [2] 36 9c [2] 71 8d [2] 3f 81 [2] 33 8b [2] 24 80 [2] 3f ce [2] 02 }

  condition:
    any of them
}