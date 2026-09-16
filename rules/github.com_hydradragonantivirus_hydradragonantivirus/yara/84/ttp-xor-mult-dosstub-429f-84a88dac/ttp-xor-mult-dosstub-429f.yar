rule TTP_XOR_MULT_DOSStub_429f {
  strings:
    $key_429f = { 16 f7 [2] 62 ef [2] 25 ed [2] 62 fc [2] 2c f0 [2] 20 fa [2] 37 f1 [2] 2c bf [2] 11 }

  condition:
    any of them
}