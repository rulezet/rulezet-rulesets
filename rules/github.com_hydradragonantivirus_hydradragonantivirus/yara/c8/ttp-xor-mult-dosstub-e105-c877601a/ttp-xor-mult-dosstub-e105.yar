rule TTP_XOR_MULT_DOSStub_e105 {
  strings:
    $key_e105 = { b5 6d [2] c1 75 [2] 86 77 [2] c1 66 [2] 8f 6a [2] 83 60 [2] 94 6b [2] 8f 25 [2] b2 }

  condition:
    any of them
}