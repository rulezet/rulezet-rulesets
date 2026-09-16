rule TTP_XOR_MULT_DOSStub_e434 {
  strings:
    $key_e434 = { b0 5c [2] c4 44 [2] 83 46 [2] c4 57 [2] 8a 5b [2] 86 51 [2] 91 5a [2] 8a 14 [2] b7 }

  condition:
    any of them
}