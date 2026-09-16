rule TTP_XOR_MULT_DOSStub_1aee {
  strings:
    $key_1aee = { 4e 86 [2] 3a 9e [2] 7d 9c [2] 3a 8d [2] 74 81 [2] 78 8b [2] 6f 80 [2] 74 ce [2] 49 }

  condition:
    any of them
}