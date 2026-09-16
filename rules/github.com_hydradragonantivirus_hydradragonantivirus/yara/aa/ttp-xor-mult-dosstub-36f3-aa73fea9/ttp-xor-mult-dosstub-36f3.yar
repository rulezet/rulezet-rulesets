rule TTP_XOR_MULT_DOSStub_36f3 {
  strings:
    $key_36f3 = { 62 9b [2] 16 83 [2] 51 81 [2] 16 90 [2] 58 9c [2] 54 96 [2] 43 9d [2] 58 d3 [2] 65 }

  condition:
    any of them
}