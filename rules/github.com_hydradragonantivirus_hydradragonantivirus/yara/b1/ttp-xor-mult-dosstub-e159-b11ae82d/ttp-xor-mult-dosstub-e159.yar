rule TTP_XOR_MULT_DOSStub_e159 {
  strings:
    $key_e159 = { b5 31 [2] c1 29 [2] 86 2b [2] c1 3a [2] 8f 36 [2] 83 3c [2] 94 37 [2] 8f 79 [2] b2 }

  condition:
    any of them
}