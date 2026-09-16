rule TTP_XOR_MULT_DOSStub_9f8b {
  strings:
    $key_9f8b = { cb e3 [2] bf fb [2] f8 f9 [2] bf e8 [2] f1 e4 [2] fd ee [2] ea e5 [2] f1 ab [2] cc }

  condition:
    any of them
}