rule TTP_XOR_MULT_DOSStub_9f18 {
  strings:
    $key_9f18 = { cb 70 [2] bf 68 [2] f8 6a [2] bf 7b [2] f1 77 [2] fd 7d [2] ea 76 [2] f1 38 [2] cc }

  condition:
    any of them
}