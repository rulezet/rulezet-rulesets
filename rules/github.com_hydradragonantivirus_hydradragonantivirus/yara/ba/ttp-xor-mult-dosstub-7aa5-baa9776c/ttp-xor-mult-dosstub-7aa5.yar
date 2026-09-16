rule TTP_XOR_MULT_DOSStub_7aa5 {
  strings:
    $key_7aa5 = { 2e cd [2] 5a d5 [2] 1d d7 [2] 5a c6 [2] 14 ca [2] 18 c0 [2] 0f cb [2] 14 85 [2] 29 }

  condition:
    any of them
}