rule TTP_XOR_MULT_DOSStub_879f {
  strings:
    $key_879f = { d3 f7 [2] a7 ef [2] e0 ed [2] a7 fc [2] e9 f0 [2] e5 fa [2] f2 f1 [2] e9 bf [2] d4 }

  condition:
    any of them
}