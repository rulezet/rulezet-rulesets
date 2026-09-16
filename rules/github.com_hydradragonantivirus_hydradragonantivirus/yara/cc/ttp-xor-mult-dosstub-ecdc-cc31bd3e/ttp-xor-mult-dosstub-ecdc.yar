rule TTP_XOR_MULT_DOSStub_ecdc {
  strings:
    $key_ecdc = { b8 b4 [2] cc ac [2] 8b ae [2] cc bf [2] 82 b3 [2] 8e b9 [2] 99 b2 [2] 82 fc [2] bf }

  condition:
    any of them
}