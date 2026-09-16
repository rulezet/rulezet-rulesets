rule TTP_XOR_MULT_DOSStub_9f7c {
  strings:
    $key_9f7c = { cb 14 [2] bf 0c [2] f8 0e [2] bf 1f [2] f1 13 [2] fd 19 [2] ea 12 [2] f1 5c [2] cc }

  condition:
    any of them
}