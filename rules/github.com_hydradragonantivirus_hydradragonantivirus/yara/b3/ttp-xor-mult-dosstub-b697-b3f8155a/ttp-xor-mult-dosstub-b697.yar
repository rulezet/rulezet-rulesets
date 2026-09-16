rule TTP_XOR_MULT_DOSStub_b697 {
  strings:
    $key_b697 = { e2 ff [2] 96 e7 [2] d1 e5 [2] 96 f4 [2] d8 f8 [2] d4 f2 [2] c3 f9 [2] d8 b7 [2] e5 }

  condition:
    any of them
}