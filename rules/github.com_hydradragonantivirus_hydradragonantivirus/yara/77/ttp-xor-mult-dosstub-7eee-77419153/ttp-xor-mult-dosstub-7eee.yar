rule TTP_XOR_MULT_DOSStub_7eee {
  strings:
    $key_7eee = { 2a 86 [2] 5e 9e [2] 19 9c [2] 5e 8d [2] 10 81 [2] 1c 8b [2] 0b 80 [2] 10 ce [2] 2d }

  condition:
    any of them
}