rule TTP_XOR_MULT_DOSStub_16ee {
  strings:
    $key_16ee = { 42 86 [2] 36 9e [2] 71 9c [2] 36 8d [2] 78 81 [2] 74 8b [2] 63 80 [2] 78 ce [2] 45 }

  condition:
    any of them
}