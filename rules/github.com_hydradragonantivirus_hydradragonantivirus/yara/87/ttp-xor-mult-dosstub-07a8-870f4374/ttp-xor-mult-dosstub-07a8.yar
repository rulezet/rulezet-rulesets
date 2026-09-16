rule TTP_XOR_MULT_DOSStub_07a8 {
  strings:
    $key_07a8 = { 53 c0 [2] 27 d8 [2] 60 da [2] 27 cb [2] 69 c7 [2] 65 cd [2] 72 c6 [2] 69 88 [2] 54 }

  condition:
    any of them
}