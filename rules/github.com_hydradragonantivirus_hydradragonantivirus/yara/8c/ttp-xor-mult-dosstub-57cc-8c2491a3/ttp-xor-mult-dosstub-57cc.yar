rule TTP_XOR_MULT_DOSStub_57cc {
  strings:
    $key_57cc = { 03 a4 [2] 77 bc [2] 30 be [2] 77 af [2] 39 a3 [2] 35 a9 [2] 22 a2 [2] 39 ec [2] 04 }

  condition:
    any of them
}