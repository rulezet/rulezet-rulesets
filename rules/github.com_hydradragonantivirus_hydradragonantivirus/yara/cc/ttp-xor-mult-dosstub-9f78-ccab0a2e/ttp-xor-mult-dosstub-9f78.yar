rule TTP_XOR_MULT_DOSStub_9f78 {
  strings:
    $key_9f78 = { cb 10 [2] bf 08 [2] f8 0a [2] bf 1b [2] f1 17 [2] fd 1d [2] ea 16 [2] f1 58 [2] cc }

  condition:
    any of them
}