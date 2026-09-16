rule TTP_XOR_MULT_DOSStub_349c {
  strings:
    $key_349c = { 60 f4 [2] 14 ec [2] 53 ee [2] 14 ff [2] 5a f3 [2] 56 f9 [2] 41 f2 [2] 5a bc [2] 67 }

  condition:
    any of them
}