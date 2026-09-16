rule TTP_XOR_MULT_DOSStub_e145 {
  strings:
    $key_e145 = { b5 2d [2] c1 35 [2] 86 37 [2] c1 26 [2] 8f 2a [2] 83 20 [2] 94 2b [2] 8f 65 [2] b2 }

  condition:
    any of them
}