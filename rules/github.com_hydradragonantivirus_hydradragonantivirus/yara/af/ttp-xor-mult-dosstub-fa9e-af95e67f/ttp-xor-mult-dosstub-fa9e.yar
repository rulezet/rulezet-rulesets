rule TTP_XOR_MULT_DOSStub_fa9e {
  strings:
    $key_fa9e = { ae f6 [2] da ee [2] 9d ec [2] da fd [2] 94 f1 [2] 98 fb [2] 8f f0 [2] 94 be [2] a9 }

  condition:
    any of them
}