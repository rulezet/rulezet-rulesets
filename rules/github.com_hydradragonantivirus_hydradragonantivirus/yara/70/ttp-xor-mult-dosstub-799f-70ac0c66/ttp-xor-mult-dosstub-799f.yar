rule TTP_XOR_MULT_DOSStub_799f {
  strings:
    $key_799f = { 2d f7 [2] 59 ef [2] 1e ed [2] 59 fc [2] 17 f0 [2] 1b fa [2] 0c f1 [2] 17 bf [2] 2a }

  condition:
    any of them
}