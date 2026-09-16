rule TTP_XOR_MULT_DOSStub_9f3d {
  strings:
    $key_9f3d = { cb 55 [2] bf 4d [2] f8 4f [2] bf 5e [2] f1 52 [2] fd 58 [2] ea 53 [2] f1 1d [2] cc }

  condition:
    any of them
}