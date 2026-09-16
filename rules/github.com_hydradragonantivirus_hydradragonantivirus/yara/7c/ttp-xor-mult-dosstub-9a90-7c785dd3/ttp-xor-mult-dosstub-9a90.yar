rule TTP_XOR_MULT_DOSStub_9a90 {
  strings:
    $key_9a90 = { ce f8 [2] ba e0 [2] fd e2 [2] ba f3 [2] f4 ff [2] f8 f5 [2] ef fe [2] f4 b0 [2] c9 }

  condition:
    any of them
}