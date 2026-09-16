rule TTP_XOR_MULT_DOSStub_d89f {
  strings:
    $key_d89f = { 8c f7 [2] f8 ef [2] bf ed [2] f8 fc [2] b6 f0 [2] ba fa [2] ad f1 [2] b6 bf [2] 8b }

  condition:
    any of them
}