rule TTP_XOR_MULT_DOSStub_699f {
  strings:
    $key_699f = { 3d f7 [2] 49 ef [2] 0e ed [2] 49 fc [2] 07 f0 [2] 0b fa [2] 1c f1 [2] 07 bf [2] 3a }

  condition:
    any of them
}