rule TTP_XOR_MULT_DOSStub_409f {
  strings:
    $key_409f = { 14 f7 [2] 60 ef [2] 27 ed [2] 60 fc [2] 2e f0 [2] 22 fa [2] 35 f1 [2] 2e bf [2] 13 }

  condition:
    any of them
}