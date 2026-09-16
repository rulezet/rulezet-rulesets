rule TTP_XOR_MULT_DOSStub_6aa7 {
  strings:
    $key_6aa7 = { 3e cf [2] 4a d7 [2] 0d d5 [2] 4a c4 [2] 04 c8 [2] 08 c2 [2] 1f c9 [2] 04 87 [2] 39 }

  condition:
    any of them
}