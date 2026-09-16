rule TTP_XOR_MULT_DOSStub_9fc2 {
  strings:
    $key_9fc2 = { cb aa [2] bf b2 [2] f8 b0 [2] bf a1 [2] f1 ad [2] fd a7 [2] ea ac [2] f1 e2 [2] cc }

  condition:
    any of them
}