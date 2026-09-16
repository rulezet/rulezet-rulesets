rule TTP_XOR_MULT_DOSStub_3eee {
  strings:
    $key_3eee = { 6a 86 [2] 1e 9e [2] 59 9c [2] 1e 8d [2] 50 81 [2] 5c 8b [2] 4b 80 [2] 50 ce [2] 6d }

  condition:
    any of them
}