rule TTP_XOR_MULT_DOSStub_9f91 {
  strings:
    $key_9f91 = { cb f9 [2] bf e1 [2] f8 e3 [2] bf f2 [2] f1 fe [2] fd f4 [2] ea ff [2] f1 b1 [2] cc }

  condition:
    any of them
}