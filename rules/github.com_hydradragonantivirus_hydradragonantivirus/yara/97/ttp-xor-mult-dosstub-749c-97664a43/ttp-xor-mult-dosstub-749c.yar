rule TTP_XOR_MULT_DOSStub_749c {
  strings:
    $key_749c = { 20 f4 [2] 54 ec [2] 13 ee [2] 54 ff [2] 1a f3 [2] 16 f9 [2] 01 f2 [2] 1a bc [2] 27 }

  condition:
    any of them
}