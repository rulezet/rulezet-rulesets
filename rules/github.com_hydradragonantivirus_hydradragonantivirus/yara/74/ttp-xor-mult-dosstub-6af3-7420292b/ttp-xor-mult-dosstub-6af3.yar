rule TTP_XOR_MULT_DOSStub_6af3 {
  strings:
    $key_6af3 = { 3e 9b [2] 4a 83 [2] 0d 81 [2] 4a 90 [2] 04 9c [2] 08 96 [2] 1f 9d [2] 04 d3 [2] 39 }

  condition:
    any of them
}