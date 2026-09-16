rule TTP_XOR_MULT_DOSStub_5d9c {
  strings:
    $key_5d9c = { 09 f4 [2] 7d ec [2] 3a ee [2] 7d ff [2] 33 f3 [2] 3f f9 [2] 28 f2 [2] 33 bc [2] 0e }

  condition:
    any of them
}