rule TTP_XOR_MULT_DOSStub_859f {
  strings:
    $key_859f = { d1 f7 [2] a5 ef [2] e2 ed [2] a5 fc [2] eb f0 [2] e7 fa [2] f0 f1 [2] eb bf [2] d6 }

  condition:
    any of them
}