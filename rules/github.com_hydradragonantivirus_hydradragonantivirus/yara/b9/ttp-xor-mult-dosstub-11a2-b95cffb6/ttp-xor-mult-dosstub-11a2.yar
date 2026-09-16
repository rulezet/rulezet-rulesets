rule TTP_XOR_MULT_DOSStub_11a2 {
  strings:
    $key_11a2 = { 45 ca [2] 31 d2 [2] 76 d0 [2] 31 c1 [2] 7f cd [2] 73 c7 [2] 64 cc [2] 7f 82 [2] 42 }

  condition:
    any of them
}