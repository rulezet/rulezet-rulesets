rule TTP_XOR_MULT_DOSStub_b68d {
  strings:
    $key_b68d = { e2 e5 [2] 96 fd [2] d1 ff [2] 96 ee [2] d8 e2 [2] d4 e8 [2] c3 e3 [2] d8 ad [2] e5 }

  condition:
    any of them
}