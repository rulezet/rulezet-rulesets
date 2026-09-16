rule TTP_XOR_MULT_DOSStub_ec88 {
  strings:
    $key_ec88 = { b8 e0 [2] cc f8 [2] 8b fa [2] cc eb [2] 82 e7 [2] 8e ed [2] 99 e6 [2] 82 a8 [2] bf }

  condition:
    any of them
}