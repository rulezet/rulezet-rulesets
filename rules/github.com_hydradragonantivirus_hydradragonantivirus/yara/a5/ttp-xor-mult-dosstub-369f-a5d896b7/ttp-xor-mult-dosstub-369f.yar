rule TTP_XOR_MULT_DOSStub_369f {
  strings:
    $key_369f = { 62 f7 [2] 16 ef [2] 51 ed [2] 16 fc [2] 58 f0 [2] 54 fa [2] 43 f1 [2] 58 bf [2] 65 }

  condition:
    any of them
}