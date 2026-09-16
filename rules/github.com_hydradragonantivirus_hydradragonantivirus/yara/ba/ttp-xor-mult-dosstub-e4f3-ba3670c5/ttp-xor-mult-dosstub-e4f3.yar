rule TTP_XOR_MULT_DOSStub_e4f3 {
  strings:
    $key_e4f3 = { b0 9b [2] c4 83 [2] 83 81 [2] c4 90 [2] 8a 9c [2] 86 96 [2] 91 9d [2] 8a d3 [2] b7 }

  condition:
    any of them
}