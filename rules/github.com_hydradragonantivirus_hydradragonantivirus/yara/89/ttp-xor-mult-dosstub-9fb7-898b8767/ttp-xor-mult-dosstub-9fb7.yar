rule TTP_XOR_MULT_DOSStub_9fb7 {
  strings:
    $key_9fb7 = { cb df [2] bf c7 [2] f8 c5 [2] bf d4 [2] f1 d8 [2] fd d2 [2] ea d9 [2] f1 97 [2] cc }

  condition:
    any of them
}