rule TTP_XOR_MULT_DOSStub_e454 {
  strings:
    $key_e454 = { b0 3c [2] c4 24 [2] 83 26 [2] c4 37 [2] 8a 3b [2] 86 31 [2] 91 3a [2] 8a 74 [2] b7 }

  condition:
    any of them
}