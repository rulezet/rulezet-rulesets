rule TTP_XOR_MULT_DOSStub_9f09 {
  strings:
    $key_9f09 = { cb 61 [2] bf 79 [2] f8 7b [2] bf 6a [2] f1 66 [2] fd 6c [2] ea 67 [2] f1 29 [2] cc }

  condition:
    any of them
}