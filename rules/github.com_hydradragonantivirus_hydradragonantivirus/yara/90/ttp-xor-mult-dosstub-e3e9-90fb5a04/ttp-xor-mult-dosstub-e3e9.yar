rule TTP_XOR_MULT_DOSStub_e3e9 {
  strings:
    $key_e3e9 = { b7 81 [2] c3 99 [2] 84 9b [2] c3 8a [2] 8d 86 [2] 81 8c [2] 96 87 [2] 8d c9 [2] b0 }

  condition:
    any of them
}