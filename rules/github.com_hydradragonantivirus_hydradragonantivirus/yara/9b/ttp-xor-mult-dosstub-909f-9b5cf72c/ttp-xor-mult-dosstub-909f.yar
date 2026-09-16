rule TTP_XOR_MULT_DOSStub_909f {
  strings:
    $key_909f = { c4 f7 [2] b0 ef [2] f7 ed [2] b0 fc [2] fe f0 [2] f2 fa [2] e5 f1 [2] fe bf [2] c3 }

  condition:
    any of them
}