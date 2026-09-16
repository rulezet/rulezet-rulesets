rule TTP_XOR_MULT_DOSStub_3b8f {
  strings:
    $key_3b8f = { 6f e7 [2] 1b ff [2] 5c fd [2] 1b ec [2] 55 e0 [2] 59 ea [2] 4e e1 [2] 55 af [2] 68 }

  condition:
    any of them
}