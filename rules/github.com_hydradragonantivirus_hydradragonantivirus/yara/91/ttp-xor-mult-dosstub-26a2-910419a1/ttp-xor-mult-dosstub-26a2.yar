rule TTP_XOR_MULT_DOSStub_26a2 {
  strings:
    $key_26a2 = { 72 ca [2] 06 d2 [2] 41 d0 [2] 06 c1 [2] 48 cd [2] 44 c7 [2] 53 cc [2] 48 82 [2] 75 }

  condition:
    any of them
}