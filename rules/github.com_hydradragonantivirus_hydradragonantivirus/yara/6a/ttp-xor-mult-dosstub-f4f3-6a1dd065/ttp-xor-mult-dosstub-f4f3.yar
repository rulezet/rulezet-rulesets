rule TTP_XOR_MULT_DOSStub_f4f3 {
  strings:
    $key_f4f3 = { a0 9b [2] d4 83 [2] 93 81 [2] d4 90 [2] 9a 9c [2] 96 96 [2] 81 9d [2] 9a d3 [2] a7 }

  condition:
    any of them
}