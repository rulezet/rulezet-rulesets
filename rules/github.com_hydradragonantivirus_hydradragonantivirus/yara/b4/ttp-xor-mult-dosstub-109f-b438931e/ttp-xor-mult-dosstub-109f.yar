rule TTP_XOR_MULT_DOSStub_109f {
  strings:
    $key_109f = { 44 f7 [2] 30 ef [2] 77 ed [2] 30 fc [2] 7e f0 [2] 72 fa [2] 65 f1 [2] 7e bf [2] 43 }

  condition:
    any of them
}