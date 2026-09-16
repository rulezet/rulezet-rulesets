rule TTP_XOR_MULT_DOSStub_5cee {
  strings:
    $key_5cee = { 08 86 [2] 7c 9e [2] 3b 9c [2] 7c 8d [2] 32 81 [2] 3e 8b [2] 29 80 [2] 32 ce [2] 0f }

  condition:
    any of them
}