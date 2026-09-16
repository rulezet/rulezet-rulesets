rule TTP_XOR_MULT_DOSStub_019f {
  strings:
    $key_019f = { 55 f7 [2] 21 ef [2] 66 ed [2] 21 fc [2] 6f f0 [2] 63 fa [2] 74 f1 [2] 6f bf [2] 52 }

  condition:
    any of them
}