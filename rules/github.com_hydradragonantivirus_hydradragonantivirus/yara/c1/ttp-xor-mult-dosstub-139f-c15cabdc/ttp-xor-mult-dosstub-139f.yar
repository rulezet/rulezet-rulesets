rule TTP_XOR_MULT_DOSStub_139f {
  strings:
    $key_139f = { 47 f7 [2] 33 ef [2] 74 ed [2] 33 fc [2] 7d f0 [2] 71 fa [2] 66 f1 [2] 7d bf [2] 40 }

  condition:
    any of them
}