rule TTP_XOR_MULT_DOSStub_37a5 {
  strings:
    $key_37a5 = { 63 cd [2] 17 d5 [2] 50 d7 [2] 17 c6 [2] 59 ca [2] 55 c0 [2] 42 cb [2] 59 85 [2] 64 }

  condition:
    any of them
}