rule TTP_XOR_MULT_DOSStub_959f {
  strings:
    $key_959f = { c1 f7 [2] b5 ef [2] f2 ed [2] b5 fc [2] fb f0 [2] f7 fa [2] e0 f1 [2] fb bf [2] c6 }

  condition:
    any of them
}