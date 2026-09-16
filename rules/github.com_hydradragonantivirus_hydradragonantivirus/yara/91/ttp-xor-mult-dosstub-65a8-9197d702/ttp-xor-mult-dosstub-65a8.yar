rule TTP_XOR_MULT_DOSStub_65a8 {
  strings:
    $key_65a8 = { 31 c0 [2] 45 d8 [2] 02 da [2] 45 cb [2] 0b c7 [2] 07 cd [2] 10 c6 [2] 0b 88 [2] 36 }

  condition:
    any of them
}