rule TTP_XOR_MULT_DOSStub_658f {
  strings:
    $key_658f = { 31 e7 [2] 45 ff [2] 02 fd [2] 45 ec [2] 0b e0 [2] 07 ea [2] 10 e1 [2] 0b af [2] 36 }

  condition:
    any of them
}