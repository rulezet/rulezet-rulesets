rule TTP_XOR_MULT_DOSStub_b29c {
  strings:
    $key_b29c = { e6 f4 [2] 92 ec [2] d5 ee [2] 92 ff [2] dc f3 [2] d0 f9 [2] c7 f2 [2] dc bc [2] e1 }

  condition:
    any of them
}