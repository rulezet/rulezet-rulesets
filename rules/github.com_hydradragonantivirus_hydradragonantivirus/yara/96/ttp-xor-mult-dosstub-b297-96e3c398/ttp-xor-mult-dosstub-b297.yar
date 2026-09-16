rule TTP_XOR_MULT_DOSStub_b297 {
  strings:
    $key_b297 = { e6 ff [2] 92 e7 [2] d5 e5 [2] 92 f4 [2] dc f8 [2] d0 f2 [2] c7 f9 [2] dc b7 [2] e1 }

  condition:
    any of them
}