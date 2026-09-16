rule TTP_XOR_MULT_DOSStub_5b9f {
  strings:
    $key_5b9f = { 0f f7 [2] 7b ef [2] 3c ed [2] 7b fc [2] 35 f0 [2] 39 fa [2] 2e f1 [2] 35 bf [2] 08 }

  condition:
    any of them
}