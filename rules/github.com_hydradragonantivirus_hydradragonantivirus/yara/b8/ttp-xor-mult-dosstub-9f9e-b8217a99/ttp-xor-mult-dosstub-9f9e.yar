rule TTP_XOR_MULT_DOSStub_9f9e {
  strings:
    $key_9f9e = { cb f6 [2] bf ee [2] f8 ec [2] bf fd [2] f1 f1 [2] fd fb [2] ea f0 [2] f1 be [2] cc }

  condition:
    any of them
}