rule TTP_XOR_MULT_DOSStub_0ba8 {
  strings:
    $key_0ba8 = { 5f c0 [2] 2b d8 [2] 6c da [2] 2b cb [2] 65 c7 [2] 69 cd [2] 7e c6 [2] 65 88 [2] 58 }

  condition:
    any of them
}