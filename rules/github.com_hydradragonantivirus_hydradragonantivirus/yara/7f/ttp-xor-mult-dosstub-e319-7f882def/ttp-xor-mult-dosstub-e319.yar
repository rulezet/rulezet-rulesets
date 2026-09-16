rule TTP_XOR_MULT_DOSStub_e319 {
  strings:
    $key_e319 = { b7 71 [2] c3 69 [2] 84 6b [2] c3 7a [2] 8d 76 [2] 81 7c [2] 96 77 [2] 8d 39 [2] b0 }

  condition:
    any of them
}