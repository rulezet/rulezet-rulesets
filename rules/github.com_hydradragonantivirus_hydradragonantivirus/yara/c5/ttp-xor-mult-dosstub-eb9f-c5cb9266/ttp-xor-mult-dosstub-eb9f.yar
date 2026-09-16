rule TTP_XOR_MULT_DOSStub_eb9f {
  strings:
    $key_eb9f = { bf f7 [2] cb ef [2] 8c ed [2] cb fc [2] 85 f0 [2] 89 fa [2] 9e f1 [2] 85 bf [2] b8 }

  condition:
    any of them
}