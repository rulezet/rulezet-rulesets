rule TTP_XOR_MULT_DOSStub_9f4f {
  strings:
    $key_9f4f = { cb 27 [2] bf 3f [2] f8 3d [2] bf 2c [2] f1 20 [2] fd 2a [2] ea 21 [2] f1 6f [2] cc }

  condition:
    any of them
}