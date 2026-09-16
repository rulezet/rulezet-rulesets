rule TTP_XOR_MULT_DOSStub_bb9c {
  strings:
    $key_bb9c = { ef f4 [2] 9b ec [2] dc ee [2] 9b ff [2] d5 f3 [2] d9 f9 [2] ce f2 [2] d5 bc [2] e8 }

  condition:
    any of them
}