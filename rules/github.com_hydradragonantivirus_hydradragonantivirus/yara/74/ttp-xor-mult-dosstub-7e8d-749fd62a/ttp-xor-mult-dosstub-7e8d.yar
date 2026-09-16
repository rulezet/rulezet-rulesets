rule TTP_XOR_MULT_DOSStub_7e8d {
  strings:
    $key_7e8d = { 2a e5 [2] 5e fd [2] 19 ff [2] 5e ee [2] 10 e2 [2] 1c e8 [2] 0b e3 [2] 10 ad [2] 2d }

  condition:
    any of them
}