rule TTP_XOR_MULT_DOSStub_e363 {
  strings:
    $key_e363 = { b7 0b [2] c3 13 [2] 84 11 [2] c3 00 [2] 8d 0c [2] 81 06 [2] 96 0d [2] 8d 43 [2] b0 }

  condition:
    any of them
}