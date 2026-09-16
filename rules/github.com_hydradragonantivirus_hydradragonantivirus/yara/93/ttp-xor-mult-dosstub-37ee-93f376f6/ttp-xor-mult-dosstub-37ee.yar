rule TTP_XOR_MULT_DOSStub_37ee {
  strings:
    $key_37ee = { 63 86 [2] 17 9e [2] 50 9c [2] 17 8d [2] 59 81 [2] 55 8b [2] 42 80 [2] 59 ce [2] 64 }

  condition:
    any of them
}