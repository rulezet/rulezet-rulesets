rule TTP_XOR_MULT_DOSStub_06a8 {
  strings:
    $key_06a8 = { 52 c0 [2] 26 d8 [2] 61 da [2] 26 cb [2] 68 c7 [2] 64 cd [2] 73 c6 [2] 68 88 [2] 55 }

  condition:
    any of them
}