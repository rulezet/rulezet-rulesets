rule TTP_XOR_MULT_DOSStub_208f {
  strings:
    $key_208f = { 74 e7 [2] 00 ff [2] 47 fd [2] 00 ec [2] 4e e0 [2] 42 ea [2] 55 e1 [2] 4e af [2] 73 }

  condition:
    any of them
}