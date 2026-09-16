rule TTP_XOR_MULT_DOSStub_7b9c {
  strings:
    $key_7b9c = { 2f f4 [2] 5b ec [2] 1c ee [2] 5b ff [2] 15 f3 [2] 19 f9 [2] 0e f2 [2] 15 bc [2] 28 }

  condition:
    any of them
}