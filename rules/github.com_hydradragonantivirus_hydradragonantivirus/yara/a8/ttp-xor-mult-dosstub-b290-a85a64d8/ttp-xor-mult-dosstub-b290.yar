rule TTP_XOR_MULT_DOSStub_b290 {
  strings:
    $key_b290 = { e6 f8 [2] 92 e0 [2] d5 e2 [2] 92 f3 [2] dc ff [2] d0 f5 [2] c7 fe [2] dc b0 [2] e1 }

  condition:
    any of them
}