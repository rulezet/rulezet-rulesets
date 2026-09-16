rule TTP_XOR_MULT_DOSStub_688d {
  strings:
    $key_688d = { 3c e5 [2] 48 fd [2] 0f ff [2] 48 ee [2] 06 e2 [2] 0a e8 [2] 1d e3 [2] 06 ad [2] 3b }

  condition:
    any of them
}