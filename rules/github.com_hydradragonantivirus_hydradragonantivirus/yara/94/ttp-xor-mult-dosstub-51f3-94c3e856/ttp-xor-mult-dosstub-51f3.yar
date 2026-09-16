rule TTP_XOR_MULT_DOSStub_51f3 {
  strings:
    $key_51f3 = { 05 9b [2] 71 83 [2] 36 81 [2] 71 90 [2] 3f 9c [2] 33 96 [2] 24 9d [2] 3f d3 [2] 02 }

  condition:
    any of them
}