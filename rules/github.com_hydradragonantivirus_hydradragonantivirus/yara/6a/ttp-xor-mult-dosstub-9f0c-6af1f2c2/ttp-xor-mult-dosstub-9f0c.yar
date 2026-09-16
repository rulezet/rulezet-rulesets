rule TTP_XOR_MULT_DOSStub_9f0c {
  strings:
    $key_9f0c = { cb 64 [2] bf 7c [2] f8 7e [2] bf 6f [2] f1 63 [2] fd 69 [2] ea 62 [2] f1 2c [2] cc }

  condition:
    any of them
}