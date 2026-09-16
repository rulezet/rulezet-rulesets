rule TTP_XOR_MULT_DOSStub_9fec {
  strings:
    $key_9fec = { cb 84 [2] bf 9c [2] f8 9e [2] bf 8f [2] f1 83 [2] fd 89 [2] ea 82 [2] f1 cc [2] cc }

  condition:
    any of them
}