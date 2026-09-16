rule TTP_XOR_MULT_DOSStub_9f6d {
  strings:
    $key_9f6d = { cb 05 [2] bf 1d [2] f8 1f [2] bf 0e [2] f1 02 [2] fd 08 [2] ea 03 [2] f1 4d [2] cc }

  condition:
    any of them
}