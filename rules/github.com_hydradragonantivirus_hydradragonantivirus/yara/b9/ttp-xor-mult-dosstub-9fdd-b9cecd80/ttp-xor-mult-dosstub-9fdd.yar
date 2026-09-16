rule TTP_XOR_MULT_DOSStub_9fdd {
  strings:
    $key_9fdd = { cb b5 [2] bf ad [2] f8 af [2] bf be [2] f1 b2 [2] fd b8 [2] ea b3 [2] f1 fd [2] cc }

  condition:
    any of them
}