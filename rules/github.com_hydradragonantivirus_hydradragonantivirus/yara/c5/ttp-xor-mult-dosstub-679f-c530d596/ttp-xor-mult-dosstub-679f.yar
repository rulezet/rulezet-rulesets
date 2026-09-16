rule TTP_XOR_MULT_DOSStub_679f {
  strings:
    $key_679f = { 33 f7 [2] 47 ef [2] 00 ed [2] 47 fc [2] 09 f0 [2] 05 fa [2] 12 f1 [2] 09 bf [2] 34 }

  condition:
    any of them
}