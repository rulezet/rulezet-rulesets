rule TTP_XOR_MULT_DOSStub_53a3 {
  strings:
    $key_53a3 = { 07 cb [2] 73 d3 [2] 34 d1 [2] 73 c0 [2] 3d cc [2] 31 c6 [2] 26 cd [2] 3d 83 [2] 00 }

  condition:
    any of them
}