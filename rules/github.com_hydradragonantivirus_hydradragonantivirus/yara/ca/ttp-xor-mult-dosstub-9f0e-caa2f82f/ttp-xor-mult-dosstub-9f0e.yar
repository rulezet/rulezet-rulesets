rule TTP_XOR_MULT_DOSStub_9f0e {
  strings:
    $key_9f0e = { cb 66 [2] bf 7e [2] f8 7c [2] bf 6d [2] f1 61 [2] fd 6b [2] ea 60 [2] f1 2e [2] cc }

  condition:
    any of them
}