rule TTP_XOR_MULT_DOSStub_e69c {
  strings:
    $key_e69c = { b2 f4 [2] c6 ec [2] 81 ee [2] c6 ff [2] 88 f3 [2] 84 f9 [2] 93 f2 [2] 88 bc [2] b5 }

  condition:
    any of them
}