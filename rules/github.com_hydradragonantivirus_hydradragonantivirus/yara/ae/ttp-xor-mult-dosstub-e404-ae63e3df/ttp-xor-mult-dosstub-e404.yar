rule TTP_XOR_MULT_DOSStub_e404 {
  strings:
    $key_e404 = { b0 6c [2] c4 74 [2] 83 76 [2] c4 67 [2] 8a 6b [2] 86 61 [2] 91 6a [2] 8a 24 [2] b7 }

  condition:
    any of them
}