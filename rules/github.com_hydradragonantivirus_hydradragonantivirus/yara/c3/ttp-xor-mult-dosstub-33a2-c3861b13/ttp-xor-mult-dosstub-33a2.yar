rule TTP_XOR_MULT_DOSStub_33a2 {
  strings:
    $key_33a2 = { 67 ca [2] 13 d2 [2] 54 d0 [2] 13 c1 [2] 5d cd [2] 51 c7 [2] 46 cc [2] 5d 82 [2] 60 }

  condition:
    any of them
}