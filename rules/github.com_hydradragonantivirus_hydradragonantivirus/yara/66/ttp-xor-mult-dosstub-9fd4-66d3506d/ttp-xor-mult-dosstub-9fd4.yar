rule TTP_XOR_MULT_DOSStub_9fd4 {
  strings:
    $key_9fd4 = { cb bc [2] bf a4 [2] f8 a6 [2] bf b7 [2] f1 bb [2] fd b1 [2] ea ba [2] f1 f4 [2] cc }

  condition:
    any of them
}