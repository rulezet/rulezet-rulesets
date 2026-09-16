rule TTP_XOR_MULT_DOSStub_6ca3 {
  strings:
    $key_6ca3 = { 38 cb [2] 4c d3 [2] 0b d1 [2] 4c c0 [2] 02 cc [2] 0e c6 [2] 19 cd [2] 02 83 [2] 3f }

  condition:
    any of them
}