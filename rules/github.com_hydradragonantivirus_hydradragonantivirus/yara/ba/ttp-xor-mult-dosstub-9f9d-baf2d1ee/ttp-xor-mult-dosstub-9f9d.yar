rule TTP_XOR_MULT_DOSStub_9f9d {
  strings:
    $key_9f9d = { cb f5 [2] bf ed [2] f8 ef [2] bf fe [2] f1 f2 [2] fd f8 [2] ea f3 [2] f1 bd [2] cc }

  condition:
    any of them
}