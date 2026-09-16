rule TTP_XOR_MULT_DOSStub_089f {
  strings:
    $key_089f = { 5c f7 [2] 28 ef [2] 6f ed [2] 28 fc [2] 66 f0 [2] 6a fa [2] 7d f1 [2] 66 bf [2] 5b }

  condition:
    any of them
}