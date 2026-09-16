rule TTP_XOR_MULT_DOSStub_9f51 {
  strings:
    $key_9f51 = { cb 39 [2] bf 21 [2] f8 23 [2] bf 32 [2] f1 3e [2] fd 34 [2] ea 3f [2] f1 71 [2] cc }

  condition:
    any of them
}