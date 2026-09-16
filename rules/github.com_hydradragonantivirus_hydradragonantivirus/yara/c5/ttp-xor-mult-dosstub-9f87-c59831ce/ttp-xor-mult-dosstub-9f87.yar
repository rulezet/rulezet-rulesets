rule TTP_XOR_MULT_DOSStub_9f87 {
  strings:
    $key_9f87 = { cb ef [2] bf f7 [2] f8 f5 [2] bf e4 [2] f1 e8 [2] fd e2 [2] ea e9 [2] f1 a7 [2] cc }

  condition:
    any of them
}