rule TTP_XOR_MULT_DOSStub_9f69 {
  strings:
    $key_9f69 = { cb 01 [2] bf 19 [2] f8 1b [2] bf 0a [2] f1 06 [2] fd 0c [2] ea 07 [2] f1 49 [2] cc }

  condition:
    any of them
}