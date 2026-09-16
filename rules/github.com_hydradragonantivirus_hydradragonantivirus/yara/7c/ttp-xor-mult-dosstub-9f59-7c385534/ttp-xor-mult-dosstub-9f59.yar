rule TTP_XOR_MULT_DOSStub_9f59 {
  strings:
    $key_9f59 = { cb 31 [2] bf 29 [2] f8 2b [2] bf 3a [2] f1 36 [2] fd 3c [2] ea 37 [2] f1 79 [2] cc }

  condition:
    any of them
}