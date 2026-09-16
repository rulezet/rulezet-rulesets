rule TTP_XOR_MULT_DOSStub_599f {
  strings:
    $key_599f = { 0d f7 [2] 79 ef [2] 3e ed [2] 79 fc [2] 37 f0 [2] 3b fa [2] 2c f1 [2] 37 bf [2] 0a }

  condition:
    any of them
}