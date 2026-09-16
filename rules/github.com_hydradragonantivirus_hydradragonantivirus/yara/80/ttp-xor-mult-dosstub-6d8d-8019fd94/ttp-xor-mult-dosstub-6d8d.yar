rule TTP_XOR_MULT_DOSStub_6d8d {
  strings:
    $key_6d8d = { 39 e5 [2] 4d fd [2] 0a ff [2] 4d ee [2] 03 e2 [2] 0f e8 [2] 18 e3 [2] 03 ad [2] 3e }

  condition:
    any of them
}