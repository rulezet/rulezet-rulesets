rule TTP_XOR_MULT_DOSStub_3d8d {
  strings:
    $key_3d8d = { 69 e5 [2] 1d fd [2] 5a ff [2] 1d ee [2] 53 e2 [2] 5f e8 [2] 48 e3 [2] 53 ad [2] 6e }

  condition:
    any of them
}