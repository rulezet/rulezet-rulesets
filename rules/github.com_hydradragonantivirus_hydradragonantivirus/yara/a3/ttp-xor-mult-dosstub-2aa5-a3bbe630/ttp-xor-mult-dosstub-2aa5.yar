rule TTP_XOR_MULT_DOSStub_2aa5 {
  strings:
    $key_2aa5 = { 7e cd [2] 0a d5 [2] 4d d7 [2] 0a c6 [2] 44 ca [2] 48 c0 [2] 5f cb [2] 44 85 [2] 79 }

  condition:
    any of them
}