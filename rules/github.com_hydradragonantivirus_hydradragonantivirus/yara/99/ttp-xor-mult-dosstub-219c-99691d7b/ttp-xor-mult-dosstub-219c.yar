rule TTP_XOR_MULT_DOSStub_219c {
  strings:
    $key_219c = { 75 f4 [2] 01 ec [2] 46 ee [2] 01 ff [2] 4f f3 [2] 43 f9 [2] 54 f2 [2] 4f bc [2] 72 }

  condition:
    any of them
}