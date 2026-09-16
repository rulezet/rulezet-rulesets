rule TTP_XOR_MULT_DOSStub_b19c {
  strings:
    $key_b19c = { e5 f4 [2] 91 ec [2] d6 ee [2] 91 ff [2] df f3 [2] d3 f9 [2] c4 f2 [2] df bc [2] e2 }

  condition:
    any of them
}