rule TTP_XOR_MULT_DOSStub_389f {
  strings:
    $key_389f = { 6c f7 [2] 18 ef [2] 5f ed [2] 18 fc [2] 56 f0 [2] 5a fa [2] 4d f1 [2] 56 bf [2] 6b }

  condition:
    any of them
}