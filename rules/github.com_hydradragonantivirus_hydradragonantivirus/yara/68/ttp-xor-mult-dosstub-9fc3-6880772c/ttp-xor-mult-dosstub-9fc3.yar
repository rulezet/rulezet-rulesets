rule TTP_XOR_MULT_DOSStub_9fc3 {
  strings:
    $key_9fc3 = { cb ab [2] bf b3 [2] f8 b1 [2] bf a0 [2] f1 ac [2] fd a6 [2] ea ad [2] f1 e3 [2] cc }

  condition:
    any of them
}