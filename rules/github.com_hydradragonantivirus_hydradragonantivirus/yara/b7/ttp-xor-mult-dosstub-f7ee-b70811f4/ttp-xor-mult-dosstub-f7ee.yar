rule TTP_XOR_MULT_DOSStub_f7ee {
  strings:
    $key_f7ee = { a3 86 [2] d7 9e [2] 90 9c [2] d7 8d [2] 99 81 [2] 95 8b [2] 82 80 [2] 99 ce [2] a4 }

  condition:
    any of them
}