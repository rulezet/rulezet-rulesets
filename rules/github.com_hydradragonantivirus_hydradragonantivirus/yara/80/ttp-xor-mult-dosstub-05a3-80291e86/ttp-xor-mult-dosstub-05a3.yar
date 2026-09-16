rule TTP_XOR_MULT_DOSStub_05a3 {
  strings:
    $key_05a3 = { 51 cb [2] 25 d3 [2] 62 d1 [2] 25 c0 [2] 6b cc [2] 67 c6 [2] 70 cd [2] 6b 83 [2] 56 }

  condition:
    any of them
}