rule TTP_XOR_MULT_DOSStub_fbee {
  strings:
    $key_fbee = { af 86 [2] db 9e [2] 9c 9c [2] db 8d [2] 95 81 [2] 99 8b [2] 8e 80 [2] 95 ce [2] a8 }

  condition:
    any of them
}