rule TTP_XOR_MULT_DOSStub_61a8 {
  strings:
    $key_61a8 = { 35 c0 [2] 41 d8 [2] 06 da [2] 41 cb [2] 0f c7 [2] 03 cd [2] 14 c6 [2] 0f 88 [2] 32 }

  condition:
    any of them
}