rule TTP_XOR_MULT_DOSStub_b690 {
  strings:
    $key_b690 = { e2 f8 [2] 96 e0 [2] d1 e2 [2] 96 f3 [2] d8 ff [2] d4 f5 [2] c3 fe [2] d8 b0 [2] e5 }

  condition:
    any of them
}