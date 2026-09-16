rule TTP_XOR_MULT_DOSStub_40a2 {
  strings:
    $key_40a2 = { 14 ca [2] 60 d2 [2] 27 d0 [2] 60 c1 [2] 2e cd [2] 22 c7 [2] 35 cc [2] 2e 82 [2] 13 }

  condition:
    any of them
}