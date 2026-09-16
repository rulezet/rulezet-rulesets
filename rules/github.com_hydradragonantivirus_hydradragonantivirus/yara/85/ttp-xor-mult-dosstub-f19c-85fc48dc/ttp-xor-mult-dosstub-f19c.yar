rule TTP_XOR_MULT_DOSStub_f19c {
  strings:
    $key_f19c = { a5 f4 [2] d1 ec [2] 96 ee [2] d1 ff [2] 9f f3 [2] 93 f9 [2] 84 f2 [2] 9f bc [2] a2 }

  condition:
    any of them
}