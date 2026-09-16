rule TTP_XOR_MULT_DOSStub_1aa5 {
  strings:
    $key_1aa5 = { 4e cd [2] 3a d5 [2] 7d d7 [2] 3a c6 [2] 74 ca [2] 78 c0 [2] 6f cb [2] 74 85 [2] 49 }

  condition:
    any of them
}