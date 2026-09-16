rule TTP_XOR_MULT_DOSStub_0ea0 {
  strings:
    $key_0ea0 = { 5a c8 [2] 2e d0 [2] 69 d2 [2] 2e c3 [2] 60 cf [2] 6c c5 [2] 7b ce [2] 60 80 [2] 5d }

  condition:
    any of them
}