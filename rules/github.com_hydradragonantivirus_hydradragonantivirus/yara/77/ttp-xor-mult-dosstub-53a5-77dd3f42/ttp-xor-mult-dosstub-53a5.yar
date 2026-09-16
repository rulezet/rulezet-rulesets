rule TTP_XOR_MULT_DOSStub_53a5 {
  strings:
    $key_53a5 = { 07 cd [2] 73 d5 [2] 34 d7 [2] 73 c6 [2] 3d ca [2] 31 c0 [2] 26 cb [2] 3d 85 [2] 00 }

  condition:
    any of them
}