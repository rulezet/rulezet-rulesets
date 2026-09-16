rule TTP_XOR_MULT_DOSStub_288d {
  strings:
    $key_288d = { 7c e5 [2] 08 fd [2] 4f ff [2] 08 ee [2] 46 e2 [2] 4a e8 [2] 5d e3 [2] 46 ad [2] 7b }

  condition:
    any of them
}