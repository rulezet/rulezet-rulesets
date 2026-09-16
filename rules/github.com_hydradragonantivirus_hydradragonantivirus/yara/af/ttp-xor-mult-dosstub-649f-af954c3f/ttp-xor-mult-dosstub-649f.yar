rule TTP_XOR_MULT_DOSStub_649f {
  strings:
    $key_649f = { 30 f7 [2] 44 ef [2] 03 ed [2] 44 fc [2] 0a f0 [2] 06 fa [2] 11 f1 [2] 0a bf [2] 37 }

  condition:
    any of them
}