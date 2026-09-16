rule TTP_XOR_MULT_DOSStub_b18d {
  strings:
    $key_b18d = { e5 e5 [2] 91 fd [2] d6 ff [2] 91 ee [2] df e2 [2] d3 e8 [2] c4 e3 [2] df ad [2] e2 }

  condition:
    any of them
}