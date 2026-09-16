rule TTP_XOR_MULT_DOSStub_9f97 {
  strings:
    $key_9f97 = { cb ff [2] bf e7 [2] f8 e5 [2] bf f4 [2] f1 f8 [2] fd f2 [2] ea f9 [2] f1 b7 [2] cc }

  condition:
    any of them
}