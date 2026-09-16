rule TTP_XOR_MULT_DOSStub_149c {
  strings:
    $key_149c = { 40 f4 [2] 34 ec [2] 73 ee [2] 34 ff [2] 7a f3 [2] 76 f9 [2] 61 f2 [2] 7a bc [2] 47 }

  condition:
    any of them
}