rule TTP_XOR_MULT_DOSStub_e3f3 {
  strings:
    $key_e3f3 = { b7 9b [2] c3 83 [2] 84 81 [2] c3 90 [2] 8d 9c [2] 81 96 [2] 96 9d [2] 8d d3 [2] b0 }

  condition:
    any of them
}