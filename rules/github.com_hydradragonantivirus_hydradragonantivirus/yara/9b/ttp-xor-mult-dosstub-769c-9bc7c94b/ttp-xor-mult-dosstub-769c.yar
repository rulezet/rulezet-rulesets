rule TTP_XOR_MULT_DOSStub_769c {
  strings:
    $key_769c = { 22 f4 [2] 56 ec [2] 11 ee [2] 56 ff [2] 18 f3 [2] 14 f9 [2] 03 f2 [2] 18 bc [2] 25 }

  condition:
    any of them
}