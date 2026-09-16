rule TTP_XOR_MULT_DOSStub_479f {
  strings:
    $key_479f = { 13 f7 [2] 67 ef [2] 20 ed [2] 67 fc [2] 29 f0 [2] 25 fa [2] 32 f1 [2] 29 bf [2] 14 }

  condition:
    any of them
}