rule TTP_XOR_MULT_DOSStub_399f {
  strings:
    $key_399f = { 6d f7 [2] 19 ef [2] 5e ed [2] 19 fc [2] 57 f0 [2] 5b fa [2] 4c f1 [2] 57 bf [2] 6a }

  condition:
    any of them
}