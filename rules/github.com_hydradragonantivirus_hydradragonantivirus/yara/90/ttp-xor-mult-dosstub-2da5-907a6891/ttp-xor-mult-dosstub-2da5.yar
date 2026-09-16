rule TTP_XOR_MULT_DOSStub_2da5 {
  strings:
    $key_2da5 = { 79 cd [2] 0d d5 [2] 4a d7 [2] 0d c6 [2] 43 ca [2] 4f c0 [2] 58 cb [2] 43 85 [2] 7e }

  condition:
    any of them
}