rule TTP_XOR_MULT_DOSStub_48a3 {
  strings:
    $key_48a3 = { 1c cb [2] 68 d3 [2] 2f d1 [2] 68 c0 [2] 26 cc [2] 2a c6 [2] 3d cd [2] 26 83 [2] 1b }

  condition:
    any of them
}