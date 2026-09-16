rule TTP_XOR_MULT_DOSStub_7d8d {
  strings:
    $key_7d8d = { 29 e5 [2] 5d fd [2] 1a ff [2] 5d ee [2] 13 e2 [2] 1f e8 [2] 08 e3 [2] 13 ad [2] 2e }

  condition:
    any of them
}