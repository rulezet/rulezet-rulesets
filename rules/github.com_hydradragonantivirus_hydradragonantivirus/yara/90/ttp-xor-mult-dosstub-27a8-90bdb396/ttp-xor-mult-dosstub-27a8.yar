rule TTP_XOR_MULT_DOSStub_27a8 {
  strings:
    $key_27a8 = { 73 c0 [2] 07 d8 [2] 40 da [2] 07 cb [2] 49 c7 [2] 45 cd [2] 52 c6 [2] 49 88 [2] 74 }

  condition:
    any of them
}