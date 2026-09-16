rule TTP_XOR_MULT_DOSStub_249c {
  strings:
    $key_249c = { 70 f4 [2] 04 ec [2] 43 ee [2] 04 ff [2] 4a f3 [2] 46 f9 [2] 51 f2 [2] 4a bc [2] 77 }

  condition:
    any of them
}