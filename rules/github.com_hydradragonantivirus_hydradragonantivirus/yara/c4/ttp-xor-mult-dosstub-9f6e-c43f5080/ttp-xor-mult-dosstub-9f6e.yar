rule TTP_XOR_MULT_DOSStub_9f6e {
  strings:
    $key_9f6e = { cb 06 [2] bf 1e [2] f8 1c [2] bf 0d [2] f1 01 [2] fd 0b [2] ea 00 [2] f1 4e [2] cc }

  condition:
    any of them
}