rule TTP_XOR_MULT_DOSStub_0a9f {
  strings:
    $key_0a9f = { 5e f7 [2] 2a ef [2] 6d ed [2] 2a fc [2] 64 f0 [2] 68 fa [2] 7f f1 [2] 64 bf [2] 59 }

  condition:
    any of them
}