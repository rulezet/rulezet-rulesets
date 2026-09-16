rule TTP_XOR_MULT_DOSStub_d69f {
  strings:
    $key_d69f = { 82 f7 [2] f6 ef [2] b1 ed [2] f6 fc [2] b8 f0 [2] b4 fa [2] a3 f1 [2] b8 bf [2] 85 }

  condition:
    any of them
}