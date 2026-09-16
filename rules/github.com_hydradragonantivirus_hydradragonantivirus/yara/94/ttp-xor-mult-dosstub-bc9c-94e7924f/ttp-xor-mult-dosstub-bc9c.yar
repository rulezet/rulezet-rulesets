rule TTP_XOR_MULT_DOSStub_bc9c {
  strings:
    $key_bc9c = { e8 f4 [2] 9c ec [2] db ee [2] 9c ff [2] d2 f3 [2] de f9 [2] c9 f2 [2] d2 bc [2] ef }

  condition:
    any of them
}