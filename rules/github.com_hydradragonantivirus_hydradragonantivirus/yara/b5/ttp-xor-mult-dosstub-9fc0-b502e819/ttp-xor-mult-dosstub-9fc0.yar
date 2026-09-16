rule TTP_XOR_MULT_DOSStub_9fc0 {
  strings:
    $key_9fc0 = { cb a8 [2] bf b0 [2] f8 b2 [2] bf a3 [2] f1 af [2] fd a5 [2] ea ae [2] f1 e0 [2] cc }

  condition:
    any of them
}