rule TTP_XOR_MULT_DOSStub_759c {
  strings:
    $key_759c = { 21 f4 [2] 55 ec [2] 12 ee [2] 55 ff [2] 1b f3 [2] 17 f9 [2] 00 f2 [2] 1b bc [2] 26 }

  condition:
    any of them
}