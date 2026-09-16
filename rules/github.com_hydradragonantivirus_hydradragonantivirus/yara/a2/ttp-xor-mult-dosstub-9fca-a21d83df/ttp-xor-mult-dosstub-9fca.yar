rule TTP_XOR_MULT_DOSStub_9fca {
  strings:
    $key_9fca = { cb a2 [2] bf ba [2] f8 b8 [2] bf a9 [2] f1 a5 [2] fd af [2] ea a4 [2] f1 ea [2] cc }

  condition:
    any of them
}