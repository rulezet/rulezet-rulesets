rule TTP_XOR_MULT_DOSStub_76a2 {
  strings:
    $key_76a2 = { 22 ca [2] 56 d2 [2] 11 d0 [2] 56 c1 [2] 18 cd [2] 14 c7 [2] 03 cc [2] 18 82 [2] 25 }

  condition:
    any of them
}