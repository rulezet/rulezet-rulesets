rule TTP_XOR_MULT_DOSStub_719c {
  strings:
    $key_719c = { 25 f4 [2] 51 ec [2] 16 ee [2] 51 ff [2] 1f f3 [2] 13 f9 [2] 04 f2 [2] 1f bc [2] 22 }

  condition:
    any of them
}