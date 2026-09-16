rule TTP_XOR_MULT_DOSStub_9058 {
  strings:
    $key_9058 = { c4 30 [2] b0 28 [2] f7 2a [2] b0 3b [2] fe 37 [2] f2 3d [2] e5 36 [2] fe 78 [2] c3 }

  condition:
    any of them
}