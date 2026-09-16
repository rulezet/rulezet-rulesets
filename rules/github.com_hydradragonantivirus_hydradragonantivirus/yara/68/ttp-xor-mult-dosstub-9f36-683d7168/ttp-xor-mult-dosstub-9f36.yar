rule TTP_XOR_MULT_DOSStub_9f36 {
  strings:
    $key_9f36 = { cb 5e [2] bf 46 [2] f8 44 [2] bf 55 [2] f1 59 [2] fd 53 [2] ea 58 [2] f1 16 [2] cc }

  condition:
    any of them
}