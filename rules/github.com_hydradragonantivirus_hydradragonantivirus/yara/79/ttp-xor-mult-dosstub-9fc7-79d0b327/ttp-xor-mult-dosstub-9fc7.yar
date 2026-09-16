rule TTP_XOR_MULT_DOSStub_9fc7 {
  strings:
    $key_9fc7 = { cb af [2] bf b7 [2] f8 b5 [2] bf a4 [2] f1 a8 [2] fd a2 [2] ea a9 [2] f1 e7 [2] cc }

  condition:
    any of them
}