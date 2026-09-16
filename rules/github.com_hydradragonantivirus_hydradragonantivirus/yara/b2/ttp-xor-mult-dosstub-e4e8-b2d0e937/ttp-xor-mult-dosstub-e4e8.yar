rule TTP_XOR_MULT_DOSStub_e4e8 {
  strings:
    $key_e4e8 = { b0 80 [2] c4 98 [2] 83 9a [2] c4 8b [2] 8a 87 [2] 86 8d [2] 91 86 [2] 8a c8 [2] b7 }

  condition:
    any of them
}