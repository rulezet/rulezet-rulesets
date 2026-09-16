rule TTP_XOR_MULT_DOSStub_529f {
  strings:
    $key_529f = { 06 f7 [2] 72 ef [2] 35 ed [2] 72 fc [2] 3c f0 [2] 30 fa [2] 27 f1 [2] 3c bf [2] 01 }

  condition:
    any of them
}