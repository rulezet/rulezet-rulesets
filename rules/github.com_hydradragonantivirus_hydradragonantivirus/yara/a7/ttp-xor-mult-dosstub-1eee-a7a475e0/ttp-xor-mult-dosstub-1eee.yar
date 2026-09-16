rule TTP_XOR_MULT_DOSStub_1eee {
  strings:
    $key_1eee = { 4a 86 [2] 3e 9e [2] 79 9c [2] 3e 8d [2] 70 81 [2] 7c 8b [2] 6b 80 [2] 70 ce [2] 4d }

  condition:
    any of them
}