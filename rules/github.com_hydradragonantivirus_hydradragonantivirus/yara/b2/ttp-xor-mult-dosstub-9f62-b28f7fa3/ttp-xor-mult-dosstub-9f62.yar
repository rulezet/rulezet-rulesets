rule TTP_XOR_MULT_DOSStub_9f62 {
  strings:
    $key_9f62 = { cb 0a [2] bf 12 [2] f8 10 [2] bf 01 [2] f1 0d [2] fd 07 [2] ea 0c [2] f1 42 [2] cc }

  condition:
    any of them
}