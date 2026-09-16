rule TTP_XOR_MULT_DOSStub_519c {
  strings:
    $key_519c = { 05 f4 [2] 71 ec [2] 36 ee [2] 71 ff [2] 3f f3 [2] 33 f9 [2] 24 f2 [2] 3f bc [2] 02 }

  condition:
    any of them
}