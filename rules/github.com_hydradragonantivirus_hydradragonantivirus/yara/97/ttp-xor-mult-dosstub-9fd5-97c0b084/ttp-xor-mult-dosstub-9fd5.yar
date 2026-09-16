rule TTP_XOR_MULT_DOSStub_9fd5 {
  strings:
    $key_9fd5 = { cb bd [2] bf a5 [2] f8 a7 [2] bf b6 [2] f1 ba [2] fd b0 [2] ea bb [2] f1 f5 [2] cc }

  condition:
    any of them
}