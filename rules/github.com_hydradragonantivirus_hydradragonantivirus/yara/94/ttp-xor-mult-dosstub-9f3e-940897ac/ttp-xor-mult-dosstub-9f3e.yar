rule TTP_XOR_MULT_DOSStub_9f3e {
  strings:
    $key_9f3e = { cb 56 [2] bf 4e [2] f8 4c [2] bf 5d [2] f1 51 [2] fd 5b [2] ea 50 [2] f1 1e [2] cc }

  condition:
    any of them
}