rule TTP_XOR_MULT_DOSStub_00a2 {
  strings:
    $key_00a2 = { 54 ca [2] 20 d2 [2] 67 d0 [2] 20 c1 [2] 6e cd [2] 62 c7 [2] 75 cc [2] 6e 82 [2] 53 }

  condition:
    any of them
}