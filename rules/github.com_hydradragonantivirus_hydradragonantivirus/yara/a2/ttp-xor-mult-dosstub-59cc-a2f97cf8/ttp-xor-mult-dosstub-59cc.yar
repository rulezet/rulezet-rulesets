rule TTP_XOR_MULT_DOSStub_59cc {
  strings:
    $key_59cc = { 0d a4 [2] 79 bc [2] 3e be [2] 79 af [2] 37 a3 [2] 3b a9 [2] 2c a2 [2] 37 ec [2] 0a }

  condition:
    any of them
}