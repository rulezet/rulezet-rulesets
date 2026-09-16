rule TTP_XOR_MULT_DOSStub_9f1c {
  strings:
    $key_9f1c = { cb 74 [2] bf 6c [2] f8 6e [2] bf 7f [2] f1 73 [2] fd 79 [2] ea 72 [2] f1 3c [2] cc }

  condition:
    any of them
}