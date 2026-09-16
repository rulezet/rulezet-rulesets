rule TTP_XOR_MULT_DOSStub_e459 {
  strings:
    $key_e459 = { b0 31 [2] c4 29 [2] 83 2b [2] c4 3a [2] 8a 36 [2] 86 3c [2] 91 37 [2] 8a 79 [2] b7 }

  condition:
    any of them
}