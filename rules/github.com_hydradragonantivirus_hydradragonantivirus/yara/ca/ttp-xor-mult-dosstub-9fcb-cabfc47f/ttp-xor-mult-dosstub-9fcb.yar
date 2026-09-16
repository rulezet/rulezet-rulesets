rule TTP_XOR_MULT_DOSStub_9fcb {
  strings:
    $key_9fcb = { cb a3 [2] bf bb [2] f8 b9 [2] bf a8 [2] f1 a4 [2] fd ae [2] ea a5 [2] f1 eb [2] cc }

  condition:
    any of them
}