rule TTP_XOR_MULT_DOSStub_37a3 {
  strings:
    $key_37a3 = { 63 cb [2] 17 d3 [2] 50 d1 [2] 17 c0 [2] 59 cc [2] 55 c6 [2] 42 cd [2] 59 83 [2] 64 }

  condition:
    any of them
}