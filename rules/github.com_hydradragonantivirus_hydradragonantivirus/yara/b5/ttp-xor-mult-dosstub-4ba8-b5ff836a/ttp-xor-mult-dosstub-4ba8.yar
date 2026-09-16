rule TTP_XOR_MULT_DOSStub_4ba8 {
  strings:
    $key_4ba8 = { 1f c0 [2] 6b d8 [2] 2c da [2] 6b cb [2] 25 c7 [2] 29 cd [2] 3e c6 [2] 25 88 [2] 18 }

  condition:
    any of them
}