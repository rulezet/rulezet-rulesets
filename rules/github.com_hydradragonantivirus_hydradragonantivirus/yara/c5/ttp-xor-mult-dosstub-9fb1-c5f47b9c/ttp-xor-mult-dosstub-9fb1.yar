rule TTP_XOR_MULT_DOSStub_9fb1 {
  strings:
    $key_9fb1 = { cb d9 [2] bf c1 [2] f8 c3 [2] bf d2 [2] f1 de [2] fd d4 [2] ea df [2] f1 91 [2] cc }

  condition:
    any of them
}