rule TTP_XOR_MULT_DOSStub_9f38 {
  strings:
    $key_9f38 = { cb 50 [2] bf 48 [2] f8 4a [2] bf 5b [2] f1 57 [2] fd 5d [2] ea 56 [2] f1 18 [2] cc }

  condition:
    any of them
}