rule TTP_XOR_MULT_DOSStub_a39f {
  strings:
    $key_a39f = { f7 f7 [2] 83 ef [2] c4 ed [2] 83 fc [2] cd f0 [2] c1 fa [2] d6 f1 [2] cd bf [2] f0 }

  condition:
    any of them
}