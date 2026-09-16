rule TTP_XOR_MULT_DOSStub_e172 {
  strings:
    $key_e172 = { b5 1a [2] c1 02 [2] 86 00 [2] c1 11 [2] 8f 1d [2] 83 17 [2] 94 1c [2] 8f 52 [2] b2 }

  condition:
    any of them
}