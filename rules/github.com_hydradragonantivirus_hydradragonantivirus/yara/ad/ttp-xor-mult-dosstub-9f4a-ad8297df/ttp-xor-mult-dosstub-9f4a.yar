rule TTP_XOR_MULT_DOSStub_9f4a {
  strings:
    $key_9f4a = { cb 22 [2] bf 3a [2] f8 38 [2] bf 29 [2] f1 25 [2] fd 2f [2] ea 24 [2] f1 6a [2] cc }

  condition:
    any of them
}