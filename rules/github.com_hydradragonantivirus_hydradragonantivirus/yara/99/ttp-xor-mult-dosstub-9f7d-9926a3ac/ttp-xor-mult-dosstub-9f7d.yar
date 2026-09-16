rule TTP_XOR_MULT_DOSStub_9f7d {
  strings:
    $key_9f7d = { cb 15 [2] bf 0d [2] f8 0f [2] bf 1e [2] f1 12 [2] fd 18 [2] ea 13 [2] f1 5d [2] cc }

  condition:
    any of them
}