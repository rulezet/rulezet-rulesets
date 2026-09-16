rule TTP_XOR_MULT_DOSStub_8c9f {
  strings:
    $key_8c9f = { d8 f7 [2] ac ef [2] eb ed [2] ac fc [2] e2 f0 [2] ee fa [2] f9 f1 [2] e2 bf [2] df }

  condition:
    any of them
}