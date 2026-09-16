rule TTP_XOR_MULT_DOSStub_e174 {
  strings:
    $key_e174 = { b5 1c [2] c1 04 [2] 86 06 [2] c1 17 [2] 8f 1b [2] 83 11 [2] 94 1a [2] 8f 54 [2] b2 }

  condition:
    any of them
}