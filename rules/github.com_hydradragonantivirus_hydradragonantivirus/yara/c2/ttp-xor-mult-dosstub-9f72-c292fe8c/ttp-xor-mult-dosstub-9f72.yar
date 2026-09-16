rule TTP_XOR_MULT_DOSStub_9f72 {
  strings:
    $key_9f72 = { cb 1a [2] bf 02 [2] f8 00 [2] bf 11 [2] f1 1d [2] fd 17 [2] ea 1c [2] f1 52 [2] cc }

  condition:
    any of them
}