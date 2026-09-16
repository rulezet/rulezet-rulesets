rule TTP_XOR_MULT_DOSStub_459f {
  strings:
    $key_459f = { 11 f7 [2] 65 ef [2] 22 ed [2] 65 fc [2] 2b f0 [2] 27 fa [2] 30 f1 [2] 2b bf [2] 16 }

  condition:
    any of them
}