rule TTP_XOR_MULT_DOSStub_9f34 {
  strings:
    $key_9f34 = { cb 5c [2] bf 44 [2] f8 46 [2] bf 57 [2] f1 5b [2] fd 51 [2] ea 5a [2] f1 14 [2] cc }

  condition:
    any of them
}