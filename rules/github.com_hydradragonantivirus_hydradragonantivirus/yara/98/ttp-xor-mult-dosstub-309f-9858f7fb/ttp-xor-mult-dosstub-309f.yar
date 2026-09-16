rule TTP_XOR_MULT_DOSStub_309f {
  strings:
    $key_309f = { 64 f7 [2] 10 ef [2] 57 ed [2] 10 fc [2] 5e f0 [2] 52 fa [2] 45 f1 [2] 5e bf [2] 63 }

  condition:
    any of them
}