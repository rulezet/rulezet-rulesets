rule TTP_XOR_MULT_DOSStub_23a8 {
  strings:
    $key_23a8 = { 77 c0 [2] 03 d8 [2] 44 da [2] 03 cb [2] 4d c7 [2] 41 cd [2] 56 c6 [2] 4d 88 [2] 70 }

  condition:
    any of them
}