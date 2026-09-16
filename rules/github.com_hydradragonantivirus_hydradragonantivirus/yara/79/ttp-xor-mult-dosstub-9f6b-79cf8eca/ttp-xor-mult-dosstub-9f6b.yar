rule TTP_XOR_MULT_DOSStub_9f6b {
  strings:
    $key_9f6b = { cb 03 [2] bf 1b [2] f8 19 [2] bf 08 [2] f1 04 [2] fd 0e [2] ea 05 [2] f1 4b [2] cc }

  condition:
    any of them
}