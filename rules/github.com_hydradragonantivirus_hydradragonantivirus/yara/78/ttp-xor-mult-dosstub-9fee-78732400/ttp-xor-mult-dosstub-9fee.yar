rule TTP_XOR_MULT_DOSStub_9fee {
  strings:
    $key_9fee = { cb 86 [2] bf 9e [2] f8 9c [2] bf 8d [2] f1 81 [2] fd 8b [2] ea 80 [2] f1 ce [2] cc }

  condition:
    any of them
}