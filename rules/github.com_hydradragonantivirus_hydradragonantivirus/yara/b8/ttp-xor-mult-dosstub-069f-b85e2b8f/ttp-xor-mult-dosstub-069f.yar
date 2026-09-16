rule TTP_XOR_MULT_DOSStub_069f {
  strings:
    $key_069f = { 52 f7 [2] 26 ef [2] 61 ed [2] 26 fc [2] 68 f0 [2] 64 fa [2] 73 f1 [2] 68 bf [2] 55 }

  condition:
    any of them
}