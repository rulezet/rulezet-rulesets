rule TTP_XOR_MULT_DOSStub_ec98 {
  strings:
    $key_ec98 = { b8 f0 [2] cc e8 [2] 8b ea [2] cc fb [2] 82 f7 [2] 8e fd [2] 99 f6 [2] 82 b8 [2] bf }

  condition:
    any of them
}