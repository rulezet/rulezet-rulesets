rule TTP_XOR_MULT_DOSStub_2ba3 {
  strings:
    $key_2ba3 = { 7f cb [2] 0b d3 [2] 4c d1 [2] 0b c0 [2] 45 cc [2] 49 c6 [2] 5e cd [2] 45 83 [2] 78 }

  condition:
    any of them
}