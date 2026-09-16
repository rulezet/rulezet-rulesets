rule TTP_XOR_MULT_DOSStub_1ba8 {
  strings:
    $key_1ba8 = { 4f c0 [2] 3b d8 [2] 7c da [2] 3b cb [2] 75 c7 [2] 79 cd [2] 6e c6 [2] 75 88 [2] 48 }

  condition:
    any of them
}