rule TTP_XOR_MULT_DOSStub_01a2 {
  strings:
    $key_01a2 = { 55 ca [2] 21 d2 [2] 66 d0 [2] 21 c1 [2] 6f cd [2] 63 c7 [2] 74 cc [2] 6f 82 [2] 52 }

  condition:
    any of them
}