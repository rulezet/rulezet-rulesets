rule TTP_XOR_MULT_DOSStub_7a9f {
  strings:
    $key_7a9f = { 2e f7 [2] 5a ef [2] 1d ed [2] 5a fc [2] 14 f0 [2] 18 fa [2] 0f f1 [2] 14 bf [2] 29 }

  condition:
    any of them
}