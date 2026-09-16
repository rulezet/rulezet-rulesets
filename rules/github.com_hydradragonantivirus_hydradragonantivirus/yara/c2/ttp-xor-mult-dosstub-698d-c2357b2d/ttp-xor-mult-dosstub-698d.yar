rule TTP_XOR_MULT_DOSStub_698d {
  strings:
    $key_698d = { 3d e5 [2] 49 fd [2] 0e ff [2] 49 ee [2] 07 e2 [2] 0b e8 [2] 1c e3 [2] 07 ad [2] 3a }

  condition:
    any of them
}