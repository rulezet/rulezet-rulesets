rule TTP_XOR_MULT_DOSStub_9f39 {
  strings:
    $key_9f39 = { cb 51 [2] bf 49 [2] f8 4b [2] bf 5a [2] f1 56 [2] fd 5c [2] ea 57 [2] f1 19 [2] cc }

  condition:
    any of them
}