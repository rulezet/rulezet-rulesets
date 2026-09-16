rule TTP_XOR_MULT_DOSStub_709c {
  strings:
    $key_709c = { 24 f4 [2] 50 ec [2] 17 ee [2] 50 ff [2] 1e f3 [2] 12 f9 [2] 05 f2 [2] 1e bc [2] 23 }

  condition:
    any of them
}