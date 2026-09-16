rule TTP_XOR_MULT_DOSStub_618f {
  strings:
    $key_618f = { 35 e7 [2] 41 ff [2] 06 fd [2] 41 ec [2] 0f e0 [2] 03 ea [2] 14 e1 [2] 0f af [2] 32 }

  condition:
    any of them
}