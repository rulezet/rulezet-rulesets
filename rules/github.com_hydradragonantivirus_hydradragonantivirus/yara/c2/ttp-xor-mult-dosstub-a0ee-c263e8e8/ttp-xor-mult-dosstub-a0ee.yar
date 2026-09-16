rule TTP_XOR_MULT_DOSStub_a0ee {
  strings:
    $key_a0ee = { f4 86 [2] 80 9e [2] c7 9c [2] 80 8d [2] ce 81 [2] c2 8b [2] d5 80 [2] ce ce [2] f3 }

  condition:
    any of them
}