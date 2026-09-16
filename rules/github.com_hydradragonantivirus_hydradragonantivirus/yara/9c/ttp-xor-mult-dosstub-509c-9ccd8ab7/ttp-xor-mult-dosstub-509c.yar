rule TTP_XOR_MULT_DOSStub_509c {
  strings:
    $key_509c = { 04 f4 [2] 70 ec [2] 37 ee [2] 70 ff [2] 3e f3 [2] 32 f9 [2] 25 f2 [2] 3e bc [2] 03 }

  condition:
    any of them
}