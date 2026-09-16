rule TTP_XOR_MULT_DOSStub_619f {
  strings:
    $key_619f = { 35 f7 [2] 41 ef [2] 06 ed [2] 41 fc [2] 0f f0 [2] 03 fa [2] 14 f1 [2] 0f bf [2] 32 }

  condition:
    any of them
}