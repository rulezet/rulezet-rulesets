rule TTP_XOR_MULT_DOSStub_0768 {
  strings:
    $key_0768 = { 53 00 [2] 27 18 [2] 60 1a [2] 27 0b [2] 69 07 [2] 65 0d [2] 72 06 [2] 69 48 [2] 54 }

  condition:
    any of them
}