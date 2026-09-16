rule TTP_XOR_MULT_DOSStub_0d8d {
  strings:
    $key_0d8d = { 59 e5 [2] 2d fd [2] 6a ff [2] 2d ee [2] 63 e2 [2] 6f e8 [2] 78 e3 [2] 63 ad [2] 5e }

  condition:
    any of them
}