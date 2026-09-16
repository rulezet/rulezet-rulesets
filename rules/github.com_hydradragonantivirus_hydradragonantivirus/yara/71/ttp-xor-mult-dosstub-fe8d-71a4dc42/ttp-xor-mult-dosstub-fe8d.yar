rule TTP_XOR_MULT_DOSStub_fe8d {
  strings:
    $key_fe8d = { aa e5 [2] de fd [2] 99 ff [2] de ee [2] 90 e2 [2] 9c e8 [2] 8b e3 [2] 90 ad [2] ad }

  condition:
    any of them
}