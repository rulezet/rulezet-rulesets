rule TTP_XOR_MULT_DOSStub_479c {
  strings:
    $key_479c = { 13 f4 [2] 67 ec [2] 20 ee [2] 67 ff [2] 29 f3 [2] 25 f9 [2] 32 f2 [2] 29 bc [2] 14 }

  condition:
    any of them
}