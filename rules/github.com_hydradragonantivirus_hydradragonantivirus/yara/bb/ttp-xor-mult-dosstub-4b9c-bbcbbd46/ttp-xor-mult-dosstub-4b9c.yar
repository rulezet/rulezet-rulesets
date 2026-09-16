rule TTP_XOR_MULT_DOSStub_4b9c {
  strings:
    $key_4b9c = { 1f f4 [2] 6b ec [2] 2c ee [2] 6b ff [2] 25 f3 [2] 29 f9 [2] 3e f2 [2] 25 bc [2] 18 }

  condition:
    any of them
}