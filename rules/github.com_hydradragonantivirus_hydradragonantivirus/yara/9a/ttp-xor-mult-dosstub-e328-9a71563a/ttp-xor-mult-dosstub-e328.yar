rule TTP_XOR_MULT_DOSStub_e328 {
  strings:
    $key_e328 = { b7 40 [2] c3 58 [2] 84 5a [2] c3 4b [2] 8d 47 [2] 81 4d [2] 96 46 [2] 8d 08 [2] b0 }

  condition:
    any of them
}