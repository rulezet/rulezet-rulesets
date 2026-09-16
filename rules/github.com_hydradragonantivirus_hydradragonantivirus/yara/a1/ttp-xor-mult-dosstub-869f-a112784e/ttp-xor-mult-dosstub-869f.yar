rule TTP_XOR_MULT_DOSStub_869f {
  strings:
    $key_869f = { d2 f7 [2] a6 ef [2] e1 ed [2] a6 fc [2] e8 f0 [2] e4 fa [2] f3 f1 [2] e8 bf [2] d5 }

  condition:
    any of them
}