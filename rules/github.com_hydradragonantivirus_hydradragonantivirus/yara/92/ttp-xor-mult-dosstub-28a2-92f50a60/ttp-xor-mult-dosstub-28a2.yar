rule TTP_XOR_MULT_DOSStub_28a2 {
  strings:
    $key_28a2 = { 7c ca [2] 08 d2 [2] 4f d0 [2] 08 c1 [2] 46 cd [2] 4a c7 [2] 5d cc [2] 46 82 [2] 7b }

  condition:
    any of them
}