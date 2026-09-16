rule TTP_XOR_MULT_DOSStub_4aee {
  strings:
    $key_4aee = { 1e 86 [2] 6a 9e [2] 2d 9c [2] 6a 8d [2] 24 81 [2] 28 8b [2] 3f 80 [2] 24 ce [2] 19 }

  condition:
    any of them
}