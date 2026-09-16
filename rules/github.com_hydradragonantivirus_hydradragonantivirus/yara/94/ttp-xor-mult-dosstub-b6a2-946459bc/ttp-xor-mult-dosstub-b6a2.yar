rule TTP_XOR_MULT_DOSStub_b6a2 {
  strings:
    $key_b6a2 = { e2 ca [2] 96 d2 [2] d1 d0 [2] 96 c1 [2] d8 cd [2] d4 c7 [2] c3 cc [2] d8 82 [2] e5 }

  condition:
    any of them
}