rule TTP_XOR_MULT_DOSStub_e108 {
  strings:
    $key_e108 = { b5 60 [2] c1 78 [2] 86 7a [2] c1 6b [2] 8f 67 [2] 83 6d [2] 94 66 [2] 8f 28 [2] b2 }

  condition:
    any of them
}