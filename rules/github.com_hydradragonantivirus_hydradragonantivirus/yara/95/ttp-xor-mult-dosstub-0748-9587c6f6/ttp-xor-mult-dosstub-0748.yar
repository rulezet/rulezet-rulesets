rule TTP_XOR_MULT_DOSStub_0748 {
  strings:
    $key_0748 = { 53 20 [2] 27 38 [2] 60 3a [2] 27 2b [2] 69 27 [2] 65 2d [2] 72 26 [2] 69 68 [2] 54 }

  condition:
    any of them
}