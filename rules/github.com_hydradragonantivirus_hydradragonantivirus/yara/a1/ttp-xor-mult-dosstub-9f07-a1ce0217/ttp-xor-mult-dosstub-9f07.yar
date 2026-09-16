rule TTP_XOR_MULT_DOSStub_9f07 {
  strings:
    $key_9f07 = { cb 6f [2] bf 77 [2] f8 75 [2] bf 64 [2] f1 68 [2] fd 62 [2] ea 69 [2] f1 27 [2] cc }

  condition:
    any of them
}