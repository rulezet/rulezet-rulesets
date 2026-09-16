rule TTP_XOR_MULT_DOSStub_9f22 {
  strings:
    $key_9f22 = { cb 4a [2] bf 52 [2] f8 50 [2] bf 41 [2] f1 4d [2] fd 47 [2] ea 4c [2] f1 02 [2] cc }

  condition:
    any of them
}