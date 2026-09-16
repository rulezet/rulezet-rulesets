rule TTP_XOR_MULT_DOSStub_9f43 {
  strings:
    $key_9f43 = { cb 2b [2] bf 33 [2] f8 31 [2] bf 20 [2] f1 2c [2] fd 26 [2] ea 2d [2] f1 63 [2] cc }

  condition:
    any of them
}