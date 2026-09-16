rule TTP_XOR_MULT_DOSStub_9fc8 {
  strings:
    $key_9fc8 = { cb a0 [2] bf b8 [2] f8 ba [2] bf ab [2] f1 a7 [2] fd ad [2] ea a6 [2] f1 e8 [2] cc }

  condition:
    any of them
}