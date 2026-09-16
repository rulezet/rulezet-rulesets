rule TTP_XOR_MULT_DOSStub_9f86 {
  strings:
    $key_9f86 = { cb ee [2] bf f6 [2] f8 f4 [2] bf e5 [2] f1 e9 [2] fd e3 [2] ea e8 [2] f1 a6 [2] cc }

  condition:
    any of them
}