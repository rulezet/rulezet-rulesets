rule TTP_XOR_MULT_DOSStub_0742 {
  strings:
    $key_0742 = { 53 2a [2] 27 32 [2] 60 30 [2] 27 21 [2] 69 2d [2] 65 27 [2] 72 2c [2] 69 62 [2] 54 }

  condition:
    any of them
}