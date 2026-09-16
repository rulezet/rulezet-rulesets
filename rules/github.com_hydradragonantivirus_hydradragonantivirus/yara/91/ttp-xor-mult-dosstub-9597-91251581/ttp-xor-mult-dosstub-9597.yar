rule TTP_XOR_MULT_DOSStub_9597 {
  strings:
    $key_9597 = { c1 ff [2] b5 e7 [2] f2 e5 [2] b5 f4 [2] fb f8 [2] f7 f2 [2] e0 f9 [2] fb b7 [2] c6 }

  condition:
    any of them
}