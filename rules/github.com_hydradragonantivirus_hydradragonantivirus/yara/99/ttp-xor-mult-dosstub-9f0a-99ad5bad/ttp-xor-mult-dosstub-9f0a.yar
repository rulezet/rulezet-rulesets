rule TTP_XOR_MULT_DOSStub_9f0a {
  strings:
    $key_9f0a = { cb 62 [2] bf 7a [2] f8 78 [2] bf 69 [2] f1 65 [2] fd 6f [2] ea 64 [2] f1 2a [2] cc }

  condition:
    any of them
}