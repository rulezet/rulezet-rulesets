rule TTP_XOR_MULT_DOSStub_9fdc {
  strings:
    $key_9fdc = { cb b4 [2] bf ac [2] f8 ae [2] bf bf [2] f1 b3 [2] fd b9 [2] ea b2 [2] f1 fc [2] cc }

  condition:
    any of them
}