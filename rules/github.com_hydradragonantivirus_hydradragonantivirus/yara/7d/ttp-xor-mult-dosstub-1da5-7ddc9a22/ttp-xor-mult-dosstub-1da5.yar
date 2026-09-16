rule TTP_XOR_MULT_DOSStub_1da5 {
  strings:
    $key_1da5 = { 49 cd [2] 3d d5 [2] 7a d7 [2] 3d c6 [2] 73 ca [2] 7f c0 [2] 68 cb [2] 73 85 [2] 4e }

  condition:
    any of them
}