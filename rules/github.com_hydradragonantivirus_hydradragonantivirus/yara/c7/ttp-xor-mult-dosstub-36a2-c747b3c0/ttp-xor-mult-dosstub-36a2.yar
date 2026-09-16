rule TTP_XOR_MULT_DOSStub_36a2 {
  strings:
    $key_36a2 = { 62 ca [2] 16 d2 [2] 51 d0 [2] 16 c1 [2] 58 cd [2] 54 c7 [2] 43 cc [2] 58 82 [2] 65 }

  condition:
    any of them
}