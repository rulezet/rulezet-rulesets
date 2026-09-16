rule TTP_XOR_MULT_DOSStub_9f33 {
  strings:
    $key_9f33 = { cb 5b [2] bf 43 [2] f8 41 [2] bf 50 [2] f1 5c [2] fd 56 [2] ea 5d [2] f1 13 [2] cc }

  condition:
    any of them
}