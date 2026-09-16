rule TTP_XOR_MULT_DOSStub_e405 {
  strings:
    $key_e405 = { b0 6d [2] c4 75 [2] 83 77 [2] c4 66 [2] 8a 6a [2] 86 60 [2] 91 6b [2] 8a 25 [2] b7 }

  condition:
    any of them
}