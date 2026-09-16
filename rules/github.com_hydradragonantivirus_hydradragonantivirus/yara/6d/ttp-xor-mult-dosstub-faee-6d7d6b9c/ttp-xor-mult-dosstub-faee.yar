rule TTP_XOR_MULT_DOSStub_faee {
  strings:
    $key_faee = { ae 86 [2] da 9e [2] 9d 9c [2] da 8d [2] 94 81 [2] 98 8b [2] 8f 80 [2] 94 ce [2] a9 }

  condition:
    any of them
}