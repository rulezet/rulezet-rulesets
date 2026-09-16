rule TTP_XOR_MULT_DOSStub_b7a2 {
  strings:
    $key_b7a2 = { e3 ca [2] 97 d2 [2] d0 d0 [2] 97 c1 [2] d9 cd [2] d5 c7 [2] c2 cc [2] d9 82 [2] e4 }

  condition:
    any of them
}