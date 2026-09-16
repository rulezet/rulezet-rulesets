rule TTP_XOR_MULT_DOSStub_24f3 {
  strings:
    $key_24f3 = { 70 9b [2] 04 83 [2] 43 81 [2] 04 90 [2] 4a 9c [2] 46 96 [2] 51 9d [2] 4a d3 [2] 77 }

  condition:
    any of them
}