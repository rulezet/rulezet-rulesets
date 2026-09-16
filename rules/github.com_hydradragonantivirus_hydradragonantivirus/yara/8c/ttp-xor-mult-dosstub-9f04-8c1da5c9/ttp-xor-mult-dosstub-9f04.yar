rule TTP_XOR_MULT_DOSStub_9f04 {
  strings:
    $key_9f04 = { cb 6c [2] bf 74 [2] f8 76 [2] bf 67 [2] f1 6b [2] fd 61 [2] ea 6a [2] f1 24 [2] cc }

  condition:
    any of them
}