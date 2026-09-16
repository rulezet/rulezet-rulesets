rule TTP_XOR_MULT_DOSStub_06a3 {
  strings:
    $key_06a3 = { 52 cb [2] 26 d3 [2] 61 d1 [2] 26 c0 [2] 68 cc [2] 64 c6 [2] 73 cd [2] 68 83 [2] 55 }

  condition:
    any of them
}