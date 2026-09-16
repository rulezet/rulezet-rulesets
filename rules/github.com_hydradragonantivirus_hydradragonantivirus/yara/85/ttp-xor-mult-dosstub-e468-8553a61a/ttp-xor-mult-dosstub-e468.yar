rule TTP_XOR_MULT_DOSStub_e468 {
  strings:
    $key_e468 = { b0 00 [2] c4 18 [2] 83 1a [2] c4 0b [2] 8a 07 [2] 86 0d [2] 91 06 [2] 8a 48 [2] b7 }

  condition:
    any of them
}