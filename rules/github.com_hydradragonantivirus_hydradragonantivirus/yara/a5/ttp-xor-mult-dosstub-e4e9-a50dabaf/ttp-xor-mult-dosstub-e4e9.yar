rule TTP_XOR_MULT_DOSStub_e4e9 {
  strings:
    $key_e4e9 = { b0 81 [2] c4 99 [2] 83 9b [2] c4 8a [2] 8a 86 [2] 86 8c [2] 91 87 [2] 8a c9 [2] b7 }

  condition:
    any of them
}