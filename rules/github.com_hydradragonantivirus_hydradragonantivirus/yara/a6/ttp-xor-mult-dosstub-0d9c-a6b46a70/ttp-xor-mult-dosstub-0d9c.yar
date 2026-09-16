rule TTP_XOR_MULT_DOSStub_0d9c {
  strings:
    $key_0d9c = { 59 f4 [2] 2d ec [2] 6a ee [2] 2d ff [2] 63 f3 [2] 6f f9 [2] 78 f2 [2] 63 bc [2] 5e }

  condition:
    any of them
}