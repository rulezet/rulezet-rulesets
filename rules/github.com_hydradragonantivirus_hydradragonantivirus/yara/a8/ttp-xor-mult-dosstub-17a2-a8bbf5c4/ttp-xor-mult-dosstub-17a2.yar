rule TTP_XOR_MULT_DOSStub_17a2 {
  strings:
    $key_17a2 = { 43 ca [2] 37 d2 [2] 70 d0 [2] 37 c1 [2] 79 cd [2] 75 c7 [2] 62 cc [2] 79 82 [2] 44 }

  condition:
    any of them
}