rule TTP_XOR_MULT_DOSStub_469f {
  strings:
    $key_469f = { 12 f7 [2] 66 ef [2] 21 ed [2] 66 fc [2] 28 f0 [2] 24 fa [2] 33 f1 [2] 28 bf [2] 15 }

  condition:
    any of them
}