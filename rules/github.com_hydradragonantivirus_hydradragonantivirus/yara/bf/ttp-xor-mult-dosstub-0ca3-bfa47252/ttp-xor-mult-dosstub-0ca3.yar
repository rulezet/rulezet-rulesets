rule TTP_XOR_MULT_DOSStub_0ca3 {
  strings:
    $key_0ca3 = { 58 cb [2] 2c d3 [2] 6b d1 [2] 2c c0 [2] 62 cc [2] 6e c6 [2] 79 cd [2] 62 83 [2] 5f }

  condition:
    any of them
}