rule TTP_XOR_MULT_DOSStub_5b9c {
  strings:
    $key_5b9c = { 0f f4 [2] 7b ec [2] 3c ee [2] 7b ff [2] 35 f3 [2] 39 f9 [2] 2e f2 [2] 35 bc [2] 08 }

  condition:
    any of them
}