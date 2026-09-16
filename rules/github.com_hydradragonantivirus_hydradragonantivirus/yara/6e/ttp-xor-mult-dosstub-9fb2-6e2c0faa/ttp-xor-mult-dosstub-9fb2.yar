rule TTP_XOR_MULT_DOSStub_9fb2 {
  strings:
    $key_9fb2 = { cb da [2] bf c2 [2] f8 c0 [2] bf d1 [2] f1 dd [2] fd d7 [2] ea dc [2] f1 92 [2] cc }

  condition:
    any of them
}