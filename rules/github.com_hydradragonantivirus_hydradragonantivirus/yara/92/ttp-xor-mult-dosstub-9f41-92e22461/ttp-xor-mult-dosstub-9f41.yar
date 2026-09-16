rule TTP_XOR_MULT_DOSStub_9f41 {
  strings:
    $key_9f41 = { cb 29 [2] bf 31 [2] f8 33 [2] bf 22 [2] f1 2e [2] fd 24 [2] ea 2f [2] f1 61 [2] cc }

  condition:
    any of them
}