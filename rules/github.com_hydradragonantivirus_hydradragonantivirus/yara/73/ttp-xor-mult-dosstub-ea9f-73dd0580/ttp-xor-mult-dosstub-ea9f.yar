rule TTP_XOR_MULT_DOSStub_ea9f {
  strings:
    $key_ea9f = { be f7 [2] ca ef [2] 8d ed [2] ca fc [2] 84 f0 [2] 88 fa [2] 9f f1 [2] 84 bf [2] b9 }

  condition:
    any of them
}