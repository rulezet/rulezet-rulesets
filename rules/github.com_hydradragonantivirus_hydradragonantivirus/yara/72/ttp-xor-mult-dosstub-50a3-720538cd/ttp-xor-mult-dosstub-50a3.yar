rule TTP_XOR_MULT_DOSStub_50a3 {
  strings:
    $key_50a3 = { 04 cb [2] 70 d3 [2] 37 d1 [2] 70 c0 [2] 3e cc [2] 32 c6 [2] 25 cd [2] 3e 83 [2] 03 }

  condition:
    any of them
}