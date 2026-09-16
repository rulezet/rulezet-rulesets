rule TTP_XOR_MULT_DOSStub_9f12 {
  strings:
    $key_9f12 = { cb 7a [2] bf 62 [2] f8 60 [2] bf 71 [2] f1 7d [2] fd 77 [2] ea 7c [2] f1 32 [2] cc }

  condition:
    any of them
}