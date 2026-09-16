rule TTP_XOR_MULT_DOSStub_c69c {
  strings:
    $key_c69c = { 92 f4 [2] e6 ec [2] a1 ee [2] e6 ff [2] a8 f3 [2] a4 f9 [2] b3 f2 [2] a8 bc [2] 95 }

  condition:
    any of them
}