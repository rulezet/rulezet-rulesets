rule TTP_XOR_MULT_DOSStub_9f9c {
  strings:
    $key_9f9c = { cb f4 [2] bf ec [2] f8 ee [2] bf ff [2] f1 f3 [2] fd f9 [2] ea f2 [2] f1 bc [2] cc }

  condition:
    any of them
}