rule TTP_XOR_MULT_DOSStub_e134 {
  strings:
    $key_e134 = { b5 5c [2] c1 44 [2] 86 46 [2] c1 57 [2] 8f 5b [2] 83 51 [2] 94 5a [2] 8f 14 [2] b2 }

  condition:
    any of them
}