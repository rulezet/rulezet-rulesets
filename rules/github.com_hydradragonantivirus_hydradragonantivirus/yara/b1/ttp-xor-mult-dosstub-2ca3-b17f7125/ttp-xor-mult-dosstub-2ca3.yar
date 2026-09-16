rule TTP_XOR_MULT_DOSStub_2ca3 {
  strings:
    $key_2ca3 = { 78 cb [2] 0c d3 [2] 4b d1 [2] 0c c0 [2] 42 cc [2] 4e c6 [2] 59 cd [2] 42 83 [2] 7f }

  condition:
    any of them
}