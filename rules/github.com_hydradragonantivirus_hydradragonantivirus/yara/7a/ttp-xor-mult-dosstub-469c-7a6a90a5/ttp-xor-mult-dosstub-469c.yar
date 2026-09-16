rule TTP_XOR_MULT_DOSStub_469c {
  strings:
    $key_469c = { 12 f4 [2] 66 ec [2] 21 ee [2] 66 ff [2] 28 f3 [2] 24 f9 [2] 33 f2 [2] 28 bc [2] 15 }

  condition:
    any of them
}