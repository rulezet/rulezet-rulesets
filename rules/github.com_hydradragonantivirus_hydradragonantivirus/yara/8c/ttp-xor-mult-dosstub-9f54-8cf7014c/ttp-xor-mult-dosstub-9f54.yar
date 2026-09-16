rule TTP_XOR_MULT_DOSStub_9f54 {
  strings:
    $key_9f54 = { cb 3c [2] bf 24 [2] f8 26 [2] bf 37 [2] f1 3b [2] fd 31 [2] ea 3a [2] f1 74 [2] cc }

  condition:
    any of them
}