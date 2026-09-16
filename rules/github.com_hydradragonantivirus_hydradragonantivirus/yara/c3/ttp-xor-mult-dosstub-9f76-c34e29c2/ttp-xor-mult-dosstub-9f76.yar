rule TTP_XOR_MULT_DOSStub_9f76 {
  strings:
    $key_9f76 = { cb 1e [2] bf 06 [2] f8 04 [2] bf 15 [2] f1 19 [2] fd 13 [2] ea 18 [2] f1 56 [2] cc }

  condition:
    any of them
}