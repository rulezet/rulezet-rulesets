rule TTP_XOR_MULT_DOSStub_019c {
  strings:
    $key_019c = { 55 f4 [2] 21 ec [2] 66 ee [2] 21 ff [2] 6f f3 [2] 63 f9 [2] 74 f2 [2] 6f bc [2] 52 }

  condition:
    any of them
}