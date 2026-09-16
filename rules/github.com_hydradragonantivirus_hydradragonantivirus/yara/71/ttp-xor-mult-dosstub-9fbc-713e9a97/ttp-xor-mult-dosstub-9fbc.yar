rule TTP_XOR_MULT_DOSStub_9fbc {
  strings:
    $key_9fbc = { cb d4 [2] bf cc [2] f8 ce [2] bf df [2] f1 d3 [2] fd d9 [2] ea d2 [2] f1 9c [2] cc }

  condition:
    any of them
}