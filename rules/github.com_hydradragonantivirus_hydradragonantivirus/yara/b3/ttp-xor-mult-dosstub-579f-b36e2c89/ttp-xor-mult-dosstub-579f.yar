rule TTP_XOR_MULT_DOSStub_579f {
  strings:
    $key_579f = { 03 f7 [2] 77 ef [2] 30 ed [2] 77 fc [2] 39 f0 [2] 35 fa [2] 22 f1 [2] 39 bf [2] 04 }

  condition:
    any of them
}