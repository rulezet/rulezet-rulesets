rule TTP_XOR_MULT_DOSStub_26a8 {
  strings:
    $key_26a8 = { 72 c0 [2] 06 d8 [2] 41 da [2] 06 cb [2] 48 c7 [2] 44 cd [2] 53 c6 [2] 48 88 [2] 75 }

  condition:
    any of them
}