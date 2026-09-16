rule TTP_XOR_MULT_DOSStub_57a8 {
  strings:
    $key_57a8 = { 03 c0 [2] 77 d8 [2] 30 da [2] 77 cb [2] 39 c7 [2] 35 cd [2] 22 c6 [2] 39 88 [2] 04 }

  condition:
    any of them
}