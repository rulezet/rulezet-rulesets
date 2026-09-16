rule TTP_XOR_MULT_DOSStub_359c {
  strings:
    $key_359c = { 61 f4 [2] 15 ec [2] 52 ee [2] 15 ff [2] 5b f3 [2] 57 f9 [2] 40 f2 [2] 5b bc [2] 66 }

  condition:
    any of them
}