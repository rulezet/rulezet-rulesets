rule TTP_XOR_MULT_DOSStub_2aa7 {
  strings:
    $key_2aa7 = { 7e cf [2] 0a d7 [2] 4d d5 [2] 0a c4 [2] 44 c8 [2] 48 c2 [2] 5f c9 [2] 44 87 [2] 79 }

  condition:
    any of them
}