rule TTP_XOR_MULT_DOSStub_9f5c {
  strings:
    $key_9f5c = { cb 34 [2] bf 2c [2] f8 2e [2] bf 3f [2] f1 33 [2] fd 39 [2] ea 32 [2] f1 7c [2] cc }

  condition:
    any of them
}