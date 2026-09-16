rule TTP_XOR_MULT_DOSStub_289f {
  strings:
    $key_289f = { 7c f7 [2] 08 ef [2] 4f ed [2] 08 fc [2] 46 f0 [2] 4a fa [2] 5d f1 [2] 46 bf [2] 7b }

  condition:
    any of them
}