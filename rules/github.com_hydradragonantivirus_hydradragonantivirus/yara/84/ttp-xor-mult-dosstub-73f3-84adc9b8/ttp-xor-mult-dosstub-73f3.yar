rule TTP_XOR_MULT_DOSStub_73f3 {
  strings:
    $key_73f3 = { 27 9b [2] 53 83 [2] 14 81 [2] 53 90 [2] 1d 9c [2] 11 96 [2] 06 9d [2] 1d d3 [2] 20 }

  condition:
    any of them
}