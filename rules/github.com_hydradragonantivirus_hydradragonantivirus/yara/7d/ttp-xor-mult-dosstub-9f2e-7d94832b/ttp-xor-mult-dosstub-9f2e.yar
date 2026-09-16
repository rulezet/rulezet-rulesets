rule TTP_XOR_MULT_DOSStub_9f2e {
  strings:
    $key_9f2e = { cb 46 [2] bf 5e [2] f8 5c [2] bf 4d [2] f1 41 [2] fd 4b [2] ea 40 [2] f1 0e [2] cc }

  condition:
    any of them
}