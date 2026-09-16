rule TTP_XOR_MULT_DOSStub_5da5 {
  strings:
    $key_5da5 = { 09 cd [2] 7d d5 [2] 3a d7 [2] 7d c6 [2] 33 ca [2] 3f c0 [2] 28 cb [2] 33 85 [2] 0e }

  condition:
    any of them
}