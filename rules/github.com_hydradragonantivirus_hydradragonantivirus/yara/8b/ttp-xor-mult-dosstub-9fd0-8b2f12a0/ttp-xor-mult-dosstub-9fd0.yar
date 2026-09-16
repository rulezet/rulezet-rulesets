rule TTP_XOR_MULT_DOSStub_9fd0 {
  strings:
    $key_9fd0 = { cb b8 [2] bf a0 [2] f8 a2 [2] bf b3 [2] f1 bf [2] fd b5 [2] ea be [2] f1 f0 [2] cc }

  condition:
    any of them
}