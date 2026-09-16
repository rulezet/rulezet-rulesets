rule TTP_XOR_MULT_DOSStub_16a8 {
  strings:
    $key_16a8 = { 42 c0 [2] 36 d8 [2] 71 da [2] 36 cb [2] 78 c7 [2] 74 cd [2] 63 c6 [2] 78 88 [2] 45 }

  condition:
    any of them
}