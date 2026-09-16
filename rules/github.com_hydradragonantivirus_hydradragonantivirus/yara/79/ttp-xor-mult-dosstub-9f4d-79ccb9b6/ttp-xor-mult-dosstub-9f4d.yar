rule TTP_XOR_MULT_DOSStub_9f4d {
  strings:
    $key_9f4d = { cb 25 [2] bf 3d [2] f8 3f [2] bf 2e [2] f1 22 [2] fd 28 [2] ea 23 [2] f1 6d [2] cc }

  condition:
    any of them
}