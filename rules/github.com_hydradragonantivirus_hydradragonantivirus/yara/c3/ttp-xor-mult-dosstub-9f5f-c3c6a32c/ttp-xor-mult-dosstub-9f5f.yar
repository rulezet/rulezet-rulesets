rule TTP_XOR_MULT_DOSStub_9f5f {
  strings:
    $key_9f5f = { cb 37 [2] bf 2f [2] f8 2d [2] bf 3c [2] f1 30 [2] fd 3a [2] ea 31 [2] f1 7f [2] cc }

  condition:
    any of them
}