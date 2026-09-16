rule TTP_XOR_MULT_DOSStub_9fd7 {
  strings:
    $key_9fd7 = { cb bf [2] bf a7 [2] f8 a5 [2] bf b4 [2] f1 b8 [2] fd b2 [2] ea b9 [2] f1 f7 [2] cc }

  condition:
    any of them
}