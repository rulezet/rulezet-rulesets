rule TTP_XOR_MULT_DOSStub_9f42 {
  strings:
    $key_9f42 = { cb 2a [2] bf 32 [2] f8 30 [2] bf 21 [2] f1 2d [2] fd 27 [2] ea 2c [2] f1 62 [2] cc }

  condition:
    any of them
}