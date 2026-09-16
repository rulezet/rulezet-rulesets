rule TTP_XOR_MULT_DOSStub_c89f {
  strings:
    $key_c89f = { 9c f7 [2] e8 ef [2] af ed [2] e8 fc [2] a6 f0 [2] aa fa [2] bd f1 [2] a6 bf [2] 9b }

  condition:
    any of them
}