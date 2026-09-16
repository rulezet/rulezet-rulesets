rule TTP_XOR_MULT_DOSStub_65a3 {
  strings:
    $key_65a3 = { 31 cb [2] 45 d3 [2] 02 d1 [2] 45 c0 [2] 0b cc [2] 07 c6 [2] 10 cd [2] 0b 83 [2] 36 }

  condition:
    any of them
}