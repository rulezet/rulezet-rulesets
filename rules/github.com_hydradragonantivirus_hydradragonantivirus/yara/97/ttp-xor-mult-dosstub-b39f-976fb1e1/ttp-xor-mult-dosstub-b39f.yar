rule TTP_XOR_MULT_DOSStub_b39f {
  strings:
    $key_b39f = { e7 f7 [2] 93 ef [2] d4 ed [2] 93 fc [2] dd f0 [2] d1 fa [2] c6 f1 [2] dd bf [2] e0 }

  condition:
    any of them
}