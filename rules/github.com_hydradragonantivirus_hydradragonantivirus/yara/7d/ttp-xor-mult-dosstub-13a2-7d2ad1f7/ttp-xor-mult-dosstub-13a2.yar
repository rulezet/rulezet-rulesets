rule TTP_XOR_MULT_DOSStub_13a2 {
  strings:
    $key_13a2 = { 47 ca [2] 33 d2 [2] 74 d0 [2] 33 c1 [2] 7d cd [2] 71 c7 [2] 66 cc [2] 7d 82 [2] 40 }

  condition:
    any of them
}