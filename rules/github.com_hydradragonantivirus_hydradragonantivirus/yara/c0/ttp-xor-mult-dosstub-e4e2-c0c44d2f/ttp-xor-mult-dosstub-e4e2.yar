rule TTP_XOR_MULT_DOSStub_e4e2 {
  strings:
    $key_e4e2 = { b0 8a [2] c4 92 [2] 83 90 [2] c4 81 [2] 8a 8d [2] 86 87 [2] 91 8c [2] 8a c2 [2] b7 }

  condition:
    any of them
}