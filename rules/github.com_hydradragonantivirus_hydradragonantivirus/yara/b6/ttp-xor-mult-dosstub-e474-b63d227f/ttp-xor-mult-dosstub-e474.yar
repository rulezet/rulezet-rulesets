rule TTP_XOR_MULT_DOSStub_e474 {
  strings:
    $key_e474 = { b0 1c [2] c4 04 [2] 83 06 [2] c4 17 [2] 8a 1b [2] 86 11 [2] 91 1a [2] 8a 54 [2] b7 }

  condition:
    any of them
}