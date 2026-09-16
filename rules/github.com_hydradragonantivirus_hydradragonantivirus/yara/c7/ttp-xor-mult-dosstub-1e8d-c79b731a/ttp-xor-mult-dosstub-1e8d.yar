rule TTP_XOR_MULT_DOSStub_1e8d {
  strings:
    $key_1e8d = { 4a e5 [2] 3e fd [2] 79 ff [2] 3e ee [2] 70 e2 [2] 7c e8 [2] 6b e3 [2] 70 ad [2] 4d }

  condition:
    any of them
}