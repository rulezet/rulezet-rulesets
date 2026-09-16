rule TTP_XOR_MULT_DOSStub_72a8 {
  strings:
    $key_72a8 = { 26 c0 [2] 52 d8 [2] 15 da [2] 52 cb [2] 1c c7 [2] 10 cd [2] 07 c6 [2] 1c 88 [2] 21 }

  condition:
    any of them
}