rule TTP_XOR_MULT_DOSStub_179f {
  strings:
    $key_179f = { 43 f7 [2] 37 ef [2] 70 ed [2] 37 fc [2] 79 f0 [2] 75 fa [2] 62 f1 [2] 79 bf [2] 44 }

  condition:
    any of them
}