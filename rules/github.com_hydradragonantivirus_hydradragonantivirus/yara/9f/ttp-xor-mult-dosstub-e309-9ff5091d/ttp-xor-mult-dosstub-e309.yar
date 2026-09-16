rule TTP_XOR_MULT_DOSStub_e309 {
  strings:
    $key_e309 = { b7 61 [2] c3 79 [2] 84 7b [2] c3 6a [2] 8d 66 [2] 81 6c [2] 96 67 [2] 8d 29 [2] b0 }

  condition:
    any of them
}