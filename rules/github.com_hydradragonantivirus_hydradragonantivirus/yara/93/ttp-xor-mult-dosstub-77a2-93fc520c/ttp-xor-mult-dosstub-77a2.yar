rule TTP_XOR_MULT_DOSStub_77a2 {
  strings:
    $key_77a2 = { 23 ca [2] 57 d2 [2] 10 d0 [2] 57 c1 [2] 19 cd [2] 15 c7 [2] 02 cc [2] 19 82 [2] 24 }

  condition:
    any of them
}