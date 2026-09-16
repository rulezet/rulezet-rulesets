rule TTP_XOR_MULT_DOSStub_4da5 {
  strings:
    $key_4da5 = { 19 cd [2] 6d d5 [2] 2a d7 [2] 6d c6 [2] 23 ca [2] 2f c0 [2] 38 cb [2] 23 85 [2] 1e }

  condition:
    any of them
}