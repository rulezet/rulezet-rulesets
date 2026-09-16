rule TTP_XOR_MULT_DOSStub_07ee {
  strings:
    $key_07ee = { 53 86 [2] 27 9e [2] 60 9c [2] 27 8d [2] 69 81 [2] 65 8b [2] 72 80 [2] 69 ce [2] 54 }

  condition:
    any of them
}