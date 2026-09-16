rule TTP_XOR_MULT_DOSStub_e118 {
  strings:
    $key_e118 = { b5 70 [2] c1 68 [2] 86 6a [2] c1 7b [2] 8f 77 [2] 83 7d [2] 94 76 [2] 8f 38 [2] b2 }

  condition:
    any of them
}