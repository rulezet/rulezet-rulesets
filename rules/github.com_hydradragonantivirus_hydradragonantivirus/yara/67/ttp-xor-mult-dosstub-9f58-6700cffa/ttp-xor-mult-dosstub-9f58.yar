rule TTP_XOR_MULT_DOSStub_9f58 {
  strings:
    $key_9f58 = { cb 30 [2] bf 28 [2] f8 2a [2] bf 3b [2] f1 37 [2] fd 3d [2] ea 36 [2] f1 78 [2] cc }

  condition:
    any of them
}