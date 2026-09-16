rule TTP_XOR_MULT_DOSStub_72a3 {
  strings:
    $key_72a3 = { 26 cb [2] 52 d3 [2] 15 d1 [2] 52 c0 [2] 1c cc [2] 10 c6 [2] 07 cd [2] 1c 83 [2] 21 }

  condition:
    any of them
}