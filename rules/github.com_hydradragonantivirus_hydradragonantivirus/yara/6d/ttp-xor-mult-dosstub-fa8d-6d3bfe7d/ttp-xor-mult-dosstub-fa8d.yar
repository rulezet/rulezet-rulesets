rule TTP_XOR_MULT_DOSStub_fa8d {
  strings:
    $key_fa8d = { ae e5 [2] da fd [2] 9d ff [2] da ee [2] 94 e2 [2] 98 e8 [2] 8f e3 [2] 94 ad [2] a9 }

  condition:
    any of them
}