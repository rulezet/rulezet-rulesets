rule TTP_XOR_MULT_DOSStub_3ca3 {
  strings:
    $key_3ca3 = { 68 cb [2] 1c d3 [2] 5b d1 [2] 1c c0 [2] 52 cc [2] 5e c6 [2] 49 cd [2] 52 83 [2] 6f }

  condition:
    any of them
}