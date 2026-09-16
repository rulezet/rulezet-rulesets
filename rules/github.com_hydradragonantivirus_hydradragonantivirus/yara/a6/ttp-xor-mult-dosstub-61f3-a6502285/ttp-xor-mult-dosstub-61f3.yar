rule TTP_XOR_MULT_DOSStub_61f3 {
  strings:
    $key_61f3 = { 35 9b [2] 41 83 [2] 06 81 [2] 41 90 [2] 0f 9c [2] 03 96 [2] 14 9d [2] 0f d3 [2] 32 }

  condition:
    any of them
}