rule TTP_XOR_MULT_DOSStub_11a8 {
  strings:
    $key_11a8 = { 45 c0 [2] 31 d8 [2] 76 da [2] 31 cb [2] 7f c7 [2] 73 cd [2] 64 c6 [2] 7f 88 [2] 42 }

  condition:
    any of them
}