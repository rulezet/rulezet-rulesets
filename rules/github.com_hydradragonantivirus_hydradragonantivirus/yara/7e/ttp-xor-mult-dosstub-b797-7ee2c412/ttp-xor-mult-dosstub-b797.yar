rule TTP_XOR_MULT_DOSStub_b797 {
  strings:
    $key_b797 = { e3 ff [2] 97 e7 [2] d0 e5 [2] 97 f4 [2] d9 f8 [2] d5 f2 [2] c2 f9 [2] d9 b7 [2] e4 }

  condition:
    any of them
}