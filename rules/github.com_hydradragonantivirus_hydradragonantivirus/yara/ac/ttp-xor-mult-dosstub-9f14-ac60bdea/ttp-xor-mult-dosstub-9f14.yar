rule TTP_XOR_MULT_DOSStub_9f14 {
  strings:
    $key_9f14 = { cb 7c [2] bf 64 [2] f8 66 [2] bf 77 [2] f1 7b [2] fd 71 [2] ea 7a [2] f1 34 [2] cc }

  condition:
    any of them
}