rule TTP_XOR_MULT_DOSStub_e162 {
  strings:
    $key_e162 = { b5 0a [2] c1 12 [2] 86 10 [2] c1 01 [2] 8f 0d [2] 83 07 [2] 94 0c [2] 8f 42 [2] b2 }

  condition:
    any of them
}