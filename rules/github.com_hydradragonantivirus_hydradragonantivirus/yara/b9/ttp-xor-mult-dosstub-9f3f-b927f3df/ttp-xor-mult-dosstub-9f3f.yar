rule TTP_XOR_MULT_DOSStub_9f3f {
  strings:
    $key_9f3f = { cb 57 [2] bf 4f [2] f8 4d [2] bf 5c [2] f1 50 [2] fd 5a [2] ea 51 [2] f1 1f [2] cc }

  condition:
    any of them
}