rule TTP_XOR_MULT_DOSStub_2a9f {
  strings:
    $key_2a9f = { 7e f7 [2] 0a ef [2] 4d ed [2] 0a fc [2] 44 f0 [2] 48 fa [2] 5f f1 [2] 44 bf [2] 79 }

  condition:
    any of them
}