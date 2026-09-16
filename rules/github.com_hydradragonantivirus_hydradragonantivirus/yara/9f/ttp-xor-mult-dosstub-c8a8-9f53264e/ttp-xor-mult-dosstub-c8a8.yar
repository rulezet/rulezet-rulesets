rule TTP_XOR_MULT_DOSStub_c8a8 {
  strings:
    $key_c8a8 = { 9c c0 [2] e8 d8 [2] af da [2] e8 cb [2] a6 c7 [2] aa cd [2] bd c6 [2] a6 88 [2] 9b }

  condition:
    any of them
}