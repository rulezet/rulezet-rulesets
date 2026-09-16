rule TTP_XOR_MULT_DOSStub_9f44 {
  strings:
    $key_9f44 = { cb 2c [2] bf 34 [2] f8 36 [2] bf 27 [2] f1 2b [2] fd 21 [2] ea 2a [2] f1 64 [2] cc }

  condition:
    any of them
}