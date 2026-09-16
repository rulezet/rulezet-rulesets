rule TTP_XOR_MULT_DOSStub_419c {
  strings:
    $key_419c = { 15 f4 [2] 61 ec [2] 26 ee [2] 61 ff [2] 2f f3 [2] 23 f9 [2] 34 f2 [2] 2f bc [2] 12 }

  condition:
    any of them
}