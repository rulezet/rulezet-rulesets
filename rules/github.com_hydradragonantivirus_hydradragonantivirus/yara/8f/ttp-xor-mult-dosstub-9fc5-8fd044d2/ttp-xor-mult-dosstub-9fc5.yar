rule TTP_XOR_MULT_DOSStub_9fc5 {
  strings:
    $key_9fc5 = { cb ad [2] bf b5 [2] f8 b7 [2] bf a6 [2] f1 aa [2] fd a0 [2] ea ab [2] f1 e5 [2] cc }

  condition:
    any of them
}