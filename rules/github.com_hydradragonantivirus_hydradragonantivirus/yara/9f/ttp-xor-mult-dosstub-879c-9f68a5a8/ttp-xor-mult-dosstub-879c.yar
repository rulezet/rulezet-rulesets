rule TTP_XOR_MULT_DOSStub_879c {
  strings:
    $key_879c = { d3 f4 [2] a7 ec [2] e0 ee [2] a7 ff [2] e9 f3 [2] e5 f9 [2] f2 f2 [2] e9 bc [2] d4 }

  condition:
    any of them
}