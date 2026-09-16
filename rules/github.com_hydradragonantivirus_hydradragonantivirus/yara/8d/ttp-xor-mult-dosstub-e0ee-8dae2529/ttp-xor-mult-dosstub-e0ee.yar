rule TTP_XOR_MULT_DOSStub_e0ee {
  strings:
    $key_e0ee = { b4 86 [2] c0 9e [2] 87 9c [2] c0 8d [2] 8e 81 [2] 82 8b [2] 95 80 [2] 8e ce [2] b3 }

  condition:
    any of them
}