rule TTP_XOR_MULT_DOSStub_b28d {
  strings:
    $key_b28d = { e6 e5 [2] 92 fd [2] d5 ff [2] 92 ee [2] dc e2 [2] d0 e8 [2] c7 e3 [2] dc ad [2] e1 }

  condition:
    any of them
}