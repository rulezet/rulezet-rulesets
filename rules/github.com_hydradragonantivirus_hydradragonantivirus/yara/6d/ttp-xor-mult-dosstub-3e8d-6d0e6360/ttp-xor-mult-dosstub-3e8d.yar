rule TTP_XOR_MULT_DOSStub_3e8d {
  strings:
    $key_3e8d = { 6a e5 [2] 1e fd [2] 59 ff [2] 1e ee [2] 50 e2 [2] 5c e8 [2] 4b e3 [2] 50 ad [2] 6d }

  condition:
    any of them
}