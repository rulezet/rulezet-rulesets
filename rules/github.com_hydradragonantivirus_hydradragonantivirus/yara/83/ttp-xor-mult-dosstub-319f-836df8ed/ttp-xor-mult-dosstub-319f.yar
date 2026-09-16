rule TTP_XOR_MULT_DOSStub_319f {
  strings:
    $key_319f = { 65 f7 [2] 11 ef [2] 56 ed [2] 11 fc [2] 5f f0 [2] 53 fa [2] 44 f1 [2] 5f bf [2] 62 }

  condition:
    any of them
}