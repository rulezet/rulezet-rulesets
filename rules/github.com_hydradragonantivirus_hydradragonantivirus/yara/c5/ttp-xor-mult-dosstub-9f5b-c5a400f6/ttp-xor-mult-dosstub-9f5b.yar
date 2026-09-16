rule TTP_XOR_MULT_DOSStub_9f5b {
  strings:
    $key_9f5b = { cb 33 [2] bf 2b [2] f8 29 [2] bf 38 [2] f1 34 [2] fd 3e [2] ea 35 [2] f1 7b [2] cc }

  condition:
    any of them
}