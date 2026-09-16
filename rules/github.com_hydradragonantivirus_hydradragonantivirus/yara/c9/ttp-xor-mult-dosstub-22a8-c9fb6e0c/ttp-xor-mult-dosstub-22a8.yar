rule TTP_XOR_MULT_DOSStub_22a8 {
  strings:
    $key_22a8 = { 76 c0 [2] 02 d8 [2] 45 da [2] 02 cb [2] 4c c7 [2] 40 cd [2] 57 c6 [2] 4c 88 [2] 71 }

  condition:
    any of them
}