rule TTP_XOR_MULT_DOSStub_e0a2 {
  strings:
    $key_e0a2 = { b4 ca [2] c0 d2 [2] 87 d0 [2] c0 c1 [2] 8e cd [2] 82 c7 [2] 95 cc [2] 8e 82 [2] b3 }

  condition:
    any of them
}