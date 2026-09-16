rule TTP_XOR_MULT_DOSStub_9f81 {
  strings:
    $key_9f81 = { cb e9 [2] bf f1 [2] f8 f3 [2] bf e2 [2] f1 ee [2] fd e4 [2] ea ef [2] f1 a1 [2] cc }

  condition:
    any of them
}