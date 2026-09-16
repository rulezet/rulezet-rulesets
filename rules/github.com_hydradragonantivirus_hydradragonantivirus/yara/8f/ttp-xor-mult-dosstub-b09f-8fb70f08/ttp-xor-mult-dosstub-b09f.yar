rule TTP_XOR_MULT_DOSStub_b09f {
  strings:
    $key_b09f = { e4 f7 [2] 90 ef [2] d7 ed [2] 90 fc [2] de f0 [2] d2 fa [2] c5 f1 [2] de bf [2] e3 }

  condition:
    any of them
}