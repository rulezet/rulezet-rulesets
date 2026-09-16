rule TTP_XOR_MULT_DOSStub_b6a5 {
  strings:
    $key_b6a5 = { e2 cd [2] 96 d5 [2] d1 d7 [2] 96 c6 [2] d8 ca [2] d4 c0 [2] c3 cb [2] d8 85 [2] e5 }

  condition:
    any of them
}