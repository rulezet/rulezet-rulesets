rule TTP_XOR_MULT_DOSStub_e197 {
  strings:
    $key_e197 = { b5 ff [2] c1 e7 [2] 86 e5 [2] c1 f4 [2] 8f f8 [2] 83 f2 [2] 94 f9 [2] 8f b7 [2] b2 }

  condition:
    any of them
}