rule TTP_XOR_MULT_DOSStub_6d9c {
  strings:
    $key_6d9c = { 39 f4 [2] 4d ec [2] 0a ee [2] 4d ff [2] 03 f3 [2] 0f f9 [2] 18 f2 [2] 03 bc [2] 3e }

  condition:
    any of them
}