rule TTP_XOR_MULT_DOSStub_16a5 {
  strings:
    $key_16a5 = { 42 cd [2] 36 d5 [2] 71 d7 [2] 36 c6 [2] 78 ca [2] 74 c0 [2] 63 cb [2] 78 85 [2] 45 }

  condition:
    any of them
}