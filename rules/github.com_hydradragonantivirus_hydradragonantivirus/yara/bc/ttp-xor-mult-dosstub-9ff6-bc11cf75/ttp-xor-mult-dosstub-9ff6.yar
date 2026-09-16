rule TTP_XOR_MULT_DOSStub_9ff6 {
  strings:
    $key_9ff6 = { cb 9e [2] bf 86 [2] f8 84 [2] bf 95 [2] f1 99 [2] fd 93 [2] ea 98 [2] f1 d6 [2] cc }

  condition:
    any of them
}