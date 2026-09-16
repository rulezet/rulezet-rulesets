rule TTP_XOR_MULT_DOSStub_219f {
  strings:
    $key_219f = { 75 f7 [2] 01 ef [2] 46 ed [2] 01 fc [2] 4f f0 [2] 43 fa [2] 54 f1 [2] 4f bf [2] 72 }

  condition:
    any of them
}