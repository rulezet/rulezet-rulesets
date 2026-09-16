rule TTP_XOR_MULT_DOSStub_9f2b {
  strings:
    $key_9f2b = { cb 43 [2] bf 5b [2] f8 59 [2] bf 48 [2] f1 44 [2] fd 4e [2] ea 45 [2] f1 0b [2] cc }

  condition:
    any of them
}