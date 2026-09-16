rule TTP_XOR_MULT_DOSStub_9ff8 {
  strings:
    $key_9ff8 = { cb 90 [2] bf 88 [2] f8 8a [2] bf 9b [2] f1 97 [2] fd 9d [2] ea 96 [2] f1 d8 [2] cc }

  condition:
    any of them
}