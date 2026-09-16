rule TTP_XOR_MULT_DOSStub_9f2d {
  strings:
    $key_9f2d = { cb 45 [2] bf 5d [2] f8 5f [2] bf 4e [2] f1 42 [2] fd 48 [2] ea 43 [2] f1 0d [2] cc }

  condition:
    any of them
}