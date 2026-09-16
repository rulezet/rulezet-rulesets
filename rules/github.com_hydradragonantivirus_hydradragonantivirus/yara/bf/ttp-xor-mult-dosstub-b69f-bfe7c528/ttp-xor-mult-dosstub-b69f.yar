rule TTP_XOR_MULT_DOSStub_b69f {
  strings:
    $key_b69f = { e2 f7 [2] 96 ef [2] d1 ed [2] 96 fc [2] d8 f0 [2] d4 fa [2] c3 f1 [2] d8 bf [2] e5 }

  condition:
    any of them
}