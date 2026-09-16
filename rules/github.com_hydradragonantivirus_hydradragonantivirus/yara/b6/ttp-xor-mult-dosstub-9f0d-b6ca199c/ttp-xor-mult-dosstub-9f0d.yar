rule TTP_XOR_MULT_DOSStub_9f0d {
  strings:
    $key_9f0d = { cb 65 [2] bf 7d [2] f8 7f [2] bf 6e [2] f1 62 [2] fd 68 [2] ea 63 [2] f1 2d [2] cc }

  condition:
    any of them
}