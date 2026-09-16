rule TTP_XOR_MULT_DOSStub_1bee {
  strings:
    $key_1bee = { 4f 86 [2] 3b 9e [2] 7c 9c [2] 3b 8d [2] 75 81 [2] 79 8b [2] 6e 80 [2] 75 ce [2] 48 }

  condition:
    any of them
}