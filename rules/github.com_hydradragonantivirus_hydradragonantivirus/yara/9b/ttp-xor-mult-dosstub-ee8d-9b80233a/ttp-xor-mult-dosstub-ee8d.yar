rule TTP_XOR_MULT_DOSStub_ee8d {
  strings:
    $key_ee8d = { ba e5 [2] ce fd [2] 89 ff [2] ce ee [2] 80 e2 [2] 8c e8 [2] 9b e3 [2] 80 ad [2] bd }

  condition:
    any of them
}