rule TTP_XOR_MULT_DOSStub_6b9f {
  strings:
    $key_6b9f = { 3f f7 [2] 4b ef [2] 0c ed [2] 4b fc [2] 05 f0 [2] 09 fa [2] 1e f1 [2] 05 bf [2] 38 }

  condition:
    any of them
}