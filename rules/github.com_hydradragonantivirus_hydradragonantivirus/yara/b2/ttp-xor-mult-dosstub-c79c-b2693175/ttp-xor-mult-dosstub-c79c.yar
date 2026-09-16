rule TTP_XOR_MULT_DOSStub_c79c {
  strings:
    $key_c79c = { 93 f4 [2] e7 ec [2] a0 ee [2] e7 ff [2] a9 f3 [2] a5 f9 [2] b2 f2 [2] a9 bc [2] 94 }

  condition:
    any of them
}