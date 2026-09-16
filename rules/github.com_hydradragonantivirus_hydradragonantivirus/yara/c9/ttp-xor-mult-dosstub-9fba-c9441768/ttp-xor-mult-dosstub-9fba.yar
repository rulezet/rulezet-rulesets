rule TTP_XOR_MULT_DOSStub_9fba {
  strings:
    $key_9fba = { cb d2 [2] bf ca [2] f8 c8 [2] bf d9 [2] f1 d5 [2] fd df [2] ea d4 [2] f1 9a [2] cc }

  condition:
    any of them
}