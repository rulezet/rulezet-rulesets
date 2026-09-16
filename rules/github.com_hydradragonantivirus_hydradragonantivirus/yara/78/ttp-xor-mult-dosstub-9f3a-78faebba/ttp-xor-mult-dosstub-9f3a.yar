rule TTP_XOR_MULT_DOSStub_9f3a {
  strings:
    $key_9f3a = { cb 52 [2] bf 4a [2] f8 48 [2] bf 59 [2] f1 55 [2] fd 5f [2] ea 54 [2] f1 1a [2] cc }

  condition:
    any of them
}