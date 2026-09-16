rule TTP_XOR_MULT_DOSStub_62a3 {
  strings:
    $key_62a3 = { 36 cb [2] 42 d3 [2] 05 d1 [2] 42 c0 [2] 0c cc [2] 00 c6 [2] 17 cd [2] 0c 83 [2] 31 }

  condition:
    any of them
}