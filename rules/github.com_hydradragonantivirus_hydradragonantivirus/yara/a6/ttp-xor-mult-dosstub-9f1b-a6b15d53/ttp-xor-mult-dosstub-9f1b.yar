rule TTP_XOR_MULT_DOSStub_9f1b {
  strings:
    $key_9f1b = { cb 73 [2] bf 6b [2] f8 69 [2] bf 78 [2] f1 74 [2] fd 7e [2] ea 75 [2] f1 3b [2] cc }

  condition:
    any of them
}