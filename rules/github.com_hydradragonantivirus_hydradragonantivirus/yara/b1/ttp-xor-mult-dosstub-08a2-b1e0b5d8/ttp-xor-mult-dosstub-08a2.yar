rule TTP_XOR_MULT_DOSStub_08a2 {
  strings:
    $key_08a2 = { 5c ca [2] 28 d2 [2] 6f d0 [2] 28 c1 [2] 66 cd [2] 6a c7 [2] 7d cc [2] 66 82 [2] 5b }

  condition:
    any of them
}