rule TTP_XOR_MULT_DOSStub_16a2 {
  strings:
    $key_16a2 = { 42 ca [2] 36 d2 [2] 71 d0 [2] 36 c1 [2] 78 cd [2] 74 c7 [2] 63 cc [2] 78 82 [2] 45 }

  condition:
    any of them
}