rule TTP_XOR_MULT_DOSStub_0eee {
  strings:
    $key_0eee = { 5a 86 [2] 2e 9e [2] 69 9c [2] 2e 8d [2] 60 81 [2] 6c 8b [2] 7b 80 [2] 60 ce [2] 5d }

  condition:
    any of them
}