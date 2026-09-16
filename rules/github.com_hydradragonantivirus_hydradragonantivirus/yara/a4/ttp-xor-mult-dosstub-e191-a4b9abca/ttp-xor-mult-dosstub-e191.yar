rule TTP_XOR_MULT_DOSStub_e191 {
  strings:
    $key_e191 = { b5 f9 [2] c1 e1 [2] 86 e3 [2] c1 f2 [2] 8f fe [2] 83 f4 [2] 94 ff [2] 8f b1 [2] b2 }

  condition:
    any of them
}