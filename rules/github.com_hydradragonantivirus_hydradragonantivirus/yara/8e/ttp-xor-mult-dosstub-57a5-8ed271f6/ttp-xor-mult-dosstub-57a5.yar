rule TTP_XOR_MULT_DOSStub_57a5 {
  strings:
    $key_57a5 = { 03 cd [2] 77 d5 [2] 30 d7 [2] 77 c6 [2] 39 ca [2] 35 c0 [2] 22 cb [2] 39 85 [2] 04 }

  condition:
    any of them
}