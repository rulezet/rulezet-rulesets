rule TTP_XOR_MULT_DOSStub_2aee {
  strings:
    $key_2aee = { 7e 86 [2] 0a 9e [2] 4d 9c [2] 0a 8d [2] 44 81 [2] 48 8b [2] 5f 80 [2] 44 ce [2] 79 }

  condition:
    any of them
}