rule TTP_XOR_MULT_DOSStub_e139 {
  strings:
    $key_e139 = { b5 51 [2] c1 49 [2] 86 4b [2] c1 5a [2] 8f 56 [2] 83 5c [2] 94 57 [2] 8f 19 [2] b2 }

  condition:
    any of them
}