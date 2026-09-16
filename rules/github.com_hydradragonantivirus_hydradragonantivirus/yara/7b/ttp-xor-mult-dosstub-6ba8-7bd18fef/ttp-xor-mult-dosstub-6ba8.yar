rule TTP_XOR_MULT_DOSStub_6ba8 {
  strings:
    $key_6ba8 = { 3f c0 [2] 4b d8 [2] 0c da [2] 4b cb [2] 05 c7 [2] 09 cd [2] 1e c6 [2] 05 88 [2] 38 }

  condition:
    any of them
}