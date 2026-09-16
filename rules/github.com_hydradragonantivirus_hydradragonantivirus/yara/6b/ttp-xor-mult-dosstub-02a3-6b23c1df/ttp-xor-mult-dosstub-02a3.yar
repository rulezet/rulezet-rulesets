rule TTP_XOR_MULT_DOSStub_02a3 {
  strings:
    $key_02a3 = { 56 cb [2] 22 d3 [2] 65 d1 [2] 22 c0 [2] 6c cc [2] 60 c6 [2] 77 cd [2] 6c 83 [2] 51 }

  condition:
    any of them
}