rule TTP_XOR_MULT_DOSStub_729c {
  strings:
    $key_729c = { 26 f4 [2] 52 ec [2] 15 ee [2] 52 ff [2] 1c f3 [2] 10 f9 [2] 07 f2 [2] 1c bc [2] 21 }

  condition:
    any of them
}