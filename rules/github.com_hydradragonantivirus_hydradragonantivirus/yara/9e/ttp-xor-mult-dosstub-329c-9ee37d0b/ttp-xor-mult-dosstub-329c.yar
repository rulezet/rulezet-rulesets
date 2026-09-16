rule TTP_XOR_MULT_DOSStub_329c {
  strings:
    $key_329c = { 66 f4 [2] 12 ec [2] 55 ee [2] 12 ff [2] 5c f3 [2] 50 f9 [2] 47 f2 [2] 5c bc [2] 61 }

  condition:
    any of them
}