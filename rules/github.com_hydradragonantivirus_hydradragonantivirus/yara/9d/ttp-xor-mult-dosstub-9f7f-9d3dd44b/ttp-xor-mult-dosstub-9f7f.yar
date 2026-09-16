rule TTP_XOR_MULT_DOSStub_9f7f {
  strings:
    $key_9f7f = { cb 17 [2] bf 0f [2] f8 0d [2] bf 1c [2] f1 10 [2] fd 1a [2] ea 11 [2] f1 5f [2] cc }

  condition:
    any of them
}